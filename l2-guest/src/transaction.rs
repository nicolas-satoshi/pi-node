//! Transaction L2 và state-transition-function.
//!
//! ## Chữ ký Ed25519, không phải Sr25519
//!
//! Account L2 dùng Ed25519 vì `ed25519-dalek` hỗ trợ `no_std` chính thức và cả SP1
//! lẫn Risc0 đều có precompile cho curve25519. Hệ quả: account L2 KHÔNG dùng chung
//! khoá Sr25519 với L1; người dùng cần một cặp khoá Ed25519 riêng cho L2.
//!
//! Chữ ký được kiểm bằng `verify_strict`: từ chối khoá công khai bậc nhỏ (small
//! order) và chữ ký không chuẩn tắc — hai nguồn gây malleability của Ed25519.
//!
//! ## Chống replay chéo mạng
//!
//! Payload được ký chứa `chain_id` (cùng giá trị với `ZkChainId` trên L1), nên giao
//! dịch ký cho devnet không dùng lại được trên mạng khác dù khoá và nonce trùng.

use crate::smt::{self, AccountState, MerkleProof, SmtError};
use alloc::vec::Vec;
use ed25519_dalek::{Signature, VerifyingKey};
use parity_scale_codec::{Decode, Encode};
use sha2::{Digest, Sha256};

/// Một transaction L2 đã ký — đơn vị nhỏ nhất sequencer đưa vào batch.
///
/// Blob DA đăng on-chain là `SCALE(Vec<SignedTransaction>)` của batch.
#[derive(Encode, Decode, Clone, Debug)]
pub struct SignedTransaction {
    pub from: [u8; 32], // Ed25519 public key = account id trên L2
    pub to: [u8; 32],
    pub amount: u128,
    /// Phải bằng ĐÚNG nonce hiện tại của `from`; sau khi áp dụng, nonce tăng 1.
    pub nonce: u64,
    pub signature: [u8; 64],
}

/// Phần dữ liệu THẬT SỰ được ký (không gồm `signature`). Thứ tự field là một phần
/// của định dạng: ví/SDK phải mã hoá SCALE đúng thứ tự này rồi ký.
#[derive(Encode, Decode, Clone, Debug)]
pub struct TransferPayload {
    pub chain_id: u64,
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u128,
    pub nonce: u64,
}

/// Witness đi kèm 1 transaction: state hiện tại và Merkle proof của CẢ hai account.
///
/// Thứ tự dựng witness (sequencer, ngoài chain) PHẢI là: proof của `from` theo
/// root hiện tại; sau khi cập nhật `from`, proof của `to` theo root TRUNG GIAN.
/// Sai thứ tự thì root cuối sai và toàn batch bị từ chối (fail-closed).
#[derive(Encode, Decode, Clone)]
pub struct TxWitness {
    pub from_state: AccountState,
    pub from_proof: MerkleProof,
    pub to_state: AccountState,
    pub to_proof: MerkleProof,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TxError {
    BadSignature,
    BadNonce {
        expected: u64,
        got: u64,
    },
    InsufficientBalance,
    Overflow,
    Merkle(SmtError),
    /// `from == to` — vô nghĩa, từ chối thẳng.
    SelfTransfer,
}

impl From<SmtError> for TxError {
    fn from(e: SmtError) -> Self {
        TxError::Merkle(e)
    }
}

/// Verify chữ ký Ed25519 (chế độ nghiêm ngặt) trên `TransferPayload` của chain
/// `chain_id`.
pub fn verify_signature(tx: &SignedTransaction, chain_id: u64) -> Result<(), TxError> {
    let payload = TransferPayload {
        chain_id,
        from: tx.from,
        to: tx.to,
        amount: tx.amount,
        nonce: tx.nonce,
    };
    let message = payload.encode();

    let verifying_key = VerifyingKey::from_bytes(&tx.from).map_err(|_| TxError::BadSignature)?;
    let signature = Signature::from_bytes(&tx.signature);

    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| TxError::BadSignature)
}

/// Áp dụng 1 transaction lên state root hiện tại, trả về root mới.
pub fn apply_transaction(
    current_root: [u8; 32],
    chain_id: u64,
    tx: &SignedTransaction,
    witness: &TxWitness,
) -> Result<[u8; 32], TxError> {
    if tx.from == tx.to {
        return Err(TxError::SelfTransfer);
    }

    verify_signature(tx, chain_id)?;

    if witness.from_state.nonce != tx.nonce {
        return Err(TxError::BadNonce {
            expected: witness.from_state.nonce,
            got: tx.nonce,
        });
    }

    let new_from_balance = witness
        .from_state
        .balance
        .checked_sub(tx.amount)
        .ok_or(TxError::InsufficientBalance)?;

    let new_from_state = AccountState {
        nonce: witness
            .from_state
            .nonce
            .checked_add(1)
            .ok_or(TxError::Overflow)?,
        balance: new_from_balance,
    };

    // Bước 1: cập nhật `from` — witness của nó phải khớp root hiện tại.
    let root_after_from = smt::apply_update(
        current_root,
        &tx.from,
        witness.from_state,
        new_from_state,
        &witness.from_proof,
    )?;

    // Bước 2: cập nhật `to` trên root TRUNG GIAN.
    let new_to_balance = witness
        .to_state
        .balance
        .checked_add(tx.amount)
        .ok_or(TxError::Overflow)?;

    let new_to_state = AccountState {
        nonce: witness.to_state.nonce, // nonce của người NHẬN không đổi
        balance: new_to_balance,
    };

    let root_after_to = smt::apply_update(
        root_after_from,
        &tx.to,
        witness.to_state,
        new_to_state,
        &witness.to_proof,
    )?;

    Ok(root_after_to)
}

/// Áp dụng cả batch tuần tự — dừng ngay nếu BẤT KỲ tx nào lỗi.
pub fn apply_batch(
    old_root: [u8; 32],
    chain_id: u64,
    txs: &[(SignedTransaction, TxWitness)],
) -> Result<[u8; 32], TxError> {
    let mut root = old_root;
    for (tx, witness) in txs {
        root = apply_transaction(root, chain_id, tx, witness)?;
    }
    Ok(root)
}

/// Hash dữ liệu DA của batch: `SHA256(SCALE(Vec<SignedTransaction>))`.
///
/// Sequencer đăng đúng blob `SCALE(Vec<SignedTransaction>)` on-chain; pallet băm
/// blob nhận được bằng SHA-256 và so với giá trị này trong public values.
pub fn batch_data_hash(txs: &[(SignedTransaction, TxWitness)]) -> [u8; 32] {
    let only_txs: Vec<SignedTransaction> = txs.iter().map(|(tx, _)| tx.clone()).collect();
    let mut hasher = Sha256::new();
    hasher.update(only_txs.encode());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use ed25519_dalek::{Signer, SigningKey};

    const CHAIN_ID: u64 = 7;

    /// Khoá xác định (không cần RNG) để test lặp lại được.
    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn make_signed_transfer(
        signing_key: &SigningKey,
        chain_id: u64,
        to: [u8; 32],
        amount: u128,
        nonce: u64,
    ) -> SignedTransaction {
        let from = signing_key.verifying_key().to_bytes();
        let payload = TransferPayload {
            chain_id,
            from,
            to,
            amount,
            nonce,
        };
        let sig = signing_key.sign(&payload.encode());
        SignedTransaction {
            from,
            to,
            amount,
            nonce,
            signature: sig.to_bytes(),
        }
    }

    /// Cây tham chiếu đơn giản (chỉ cho test) để dựng root và proof độc lập với
    /// code đang được kiểm tra.
    struct TestTree {
        leaves: BTreeMap<[u8; 32], [u8; 32]>, // đường đi -> giá trị lá
    }

    fn subtree(entries: &[([u8; 32], [u8; 32])], depth: usize) -> [u8; 32] {
        if entries.is_empty() {
            return smt::empty_hash_at_height(smt::TREE_DEPTH - depth);
        }
        if depth == smt::TREE_DEPTH {
            return entries[0].1;
        }
        let (left, right): (Vec<_>, Vec<_>) = entries
            .iter()
            .cloned()
            .partition(|(path, _)| smt::path_bit(path, depth) == 0);
        let mut hasher = Sha256::new();
        hasher.update(subtree(&left, depth + 1));
        hasher.update(subtree(&right, depth + 1));
        hasher.finalize().into()
    }

    impl TestTree {
        fn new() -> Self {
            Self {
                leaves: BTreeMap::new(),
            }
        }

        fn set(&mut self, id: &[u8; 32], state: AccountState) {
            let path = smt::account_path(id);
            if state == AccountState::EMPTY {
                self.leaves.remove(&path);
            } else {
                self.leaves.insert(path, state.leaf_hash(id));
            }
        }

        fn entries(&self) -> Vec<([u8; 32], [u8; 32])> {
            self.leaves.iter().map(|(p, l)| (*p, *l)).collect()
        }

        fn root(&self) -> [u8; 32] {
            subtree(&self.entries(), 0)
        }

        fn proof(&self, id: &[u8; 32]) -> MerkleProof {
            let path = smt::account_path(id);
            let entries = self.entries();
            let mut siblings = alloc::vec![[0u8; 32]; smt::TREE_DEPTH];
            for r in 0..smt::TREE_DEPTH {
                let sibling_entries: Vec<_> = entries
                    .iter()
                    .filter(|(p, _)| {
                        (0..r).all(|i| smt::path_bit(p, i) == smt::path_bit(&path, i))
                            && smt::path_bit(p, r) != smt::path_bit(&path, r)
                    })
                    .cloned()
                    .collect();
                siblings[smt::TREE_DEPTH - 1 - r] = subtree(&sibling_entries, r + 1);
            }
            MerkleProof { siblings }
        }
    }

    #[test]
    fn test_tree_agrees_with_empty_root() {
        assert_eq!(TestTree::new().root(), smt::EMPTY_STATE_ROOT);
    }

    #[test]
    fn valid_signature_verifies_and_tampering_is_rejected() {
        let alice = key(1);
        let tx = make_signed_transfer(&alice, CHAIN_ID, [9u8; 32], 100, 0);
        assert!(verify_signature(&tx, CHAIN_ID).is_ok());

        let mut bad_amount = tx.clone();
        bad_amount.amount = 999;
        assert_eq!(
            verify_signature(&bad_amount, CHAIN_ID),
            Err(TxError::BadSignature)
        );

        // Cùng chữ ký, chain khác -> không hợp lệ (chống replay chéo mạng).
        assert_eq!(
            verify_signature(&tx, CHAIN_ID + 1),
            Err(TxError::BadSignature)
        );
    }

    #[test]
    fn small_order_public_key_is_rejected() {
        // Điểm đơn vị (y = 1) có bậc 1. `verify_strict` phải từ chối khoá này.
        let mut weak = [0u8; 32];
        weak[0] = 1;
        let tx = SignedTransaction {
            from: weak,
            to: [9u8; 32],
            amount: 1,
            nonce: 0,
            signature: [0u8; 64],
        };
        assert_eq!(verify_signature(&tx, CHAIN_ID), Err(TxError::BadSignature));
    }

    #[test]
    fn self_transfer_rejected() {
        let alice = key(1);
        let alice_id = alice.verifying_key().to_bytes();
        let tx = make_signed_transfer(&alice, CHAIN_ID, alice_id, 1, 0);

        let witness = TxWitness {
            from_state: AccountState {
                nonce: 0,
                balance: 1000,
            },
            from_proof: smt::empty_proof(),
            to_state: AccountState {
                nonce: 0,
                balance: 1000,
            },
            to_proof: smt::empty_proof(),
        };
        assert_eq!(
            apply_transaction(smt::EMPTY_STATE_ROOT, CHAIN_ID, &tx, &witness),
            Err(TxError::SelfTransfer)
        );
    }

    /// Dựng cây có Alice (nonce 0, 1000), trả về (cây, root, id, khoá).
    fn alice_tree() -> (TestTree, [u8; 32], [u8; 32], SigningKey) {
        let alice = key(1);
        let alice_id = alice.verifying_key().to_bytes();
        let mut tree = TestTree::new();
        tree.set(
            &alice_id,
            AccountState {
                nonce: 0,
                balance: 1000,
            },
        );
        let root = tree.root();
        (tree, root, alice_id, alice)
    }

    #[test]
    fn end_to_end_transfer_matches_reference_tree() {
        let (mut tree, root0, alice_id, alice) = alice_tree();
        let bob_id = [9u8; 32];

        let tx = make_signed_transfer(&alice, CHAIN_ID, bob_id, 100, 0);

        // Witness theo đúng thứ tự: from theo root0; to theo root sau khi cập nhật from.
        let from_state = AccountState {
            nonce: 0,
            balance: 1000,
        };
        let from_proof = tree.proof(&alice_id);
        tree.set(
            &alice_id,
            AccountState {
                nonce: 1,
                balance: 900,
            },
        );
        let to_state = AccountState::EMPTY;
        let to_proof = tree.proof(&bob_id);
        let witness = TxWitness {
            from_state,
            from_proof,
            to_state,
            to_proof,
        };

        tree.set(
            &bob_id,
            AccountState {
                nonce: 0,
                balance: 100,
            },
        );
        let expected_root = tree.root();

        let got = apply_transaction(root0, CHAIN_ID, &tx, &witness).unwrap();
        assert_eq!(got, expected_root);
    }

    #[test]
    fn batch_of_two_transfers_and_data_hash() {
        let (mut tree, root0, alice_id, alice) = alice_tree();
        let bob_id = [9u8; 32];

        let mut alice_state = AccountState {
            nonce: 0,
            balance: 1000,
        };
        let mut bob_state = AccountState::EMPTY;
        let mut batch = Vec::new();

        for nonce in 0..2u64 {
            let tx = make_signed_transfer(&alice, CHAIN_ID, bob_id, 100, nonce);

            let from_state = alice_state;
            let from_proof = tree.proof(&alice_id);
            alice_state = AccountState {
                nonce: nonce + 1,
                balance: alice_state.balance - 100,
            };
            tree.set(&alice_id, alice_state);

            let to_state = bob_state;
            let to_proof = tree.proof(&bob_id);
            bob_state = AccountState {
                nonce: 0,
                balance: bob_state.balance + 100,
            };
            tree.set(&bob_id, bob_state);

            batch.push((
                tx,
                TxWitness {
                    from_state,
                    from_proof,
                    to_state,
                    to_proof,
                },
            ));
        }

        let new_root = apply_batch(root0, CHAIN_ID, &batch).unwrap();
        assert_eq!(new_root, tree.root());

        // data_hash chỉ phụ thuộc vào danh sách giao dịch, không phụ thuộc witness.
        let hash = batch_data_hash(&batch);
        let mut witness_changed = batch.clone();
        witness_changed[0].1.from_state.balance += 1;
        assert_eq!(hash, batch_data_hash(&witness_changed));
        // Bỏ một giao dịch thì hash đổi.
        assert_ne!(hash, batch_data_hash(&batch[..1]));
    }

    #[test]
    fn replaying_same_transaction_fails() {
        let (mut tree, root0, alice_id, alice) = alice_tree();
        let bob_id = [9u8; 32];
        let tx = make_signed_transfer(&alice, CHAIN_ID, bob_id, 100, 0);

        let from_proof = tree.proof(&alice_id);
        tree.set(
            &alice_id,
            AccountState {
                nonce: 1,
                balance: 900,
            },
        );
        let to_proof = tree.proof(&bob_id);
        let witness = TxWitness {
            from_state: AccountState {
                nonce: 0,
                balance: 1000,
            },
            from_proof,
            to_state: AccountState::EMPTY,
            to_proof,
        };

        let root1 = apply_transaction(root0, CHAIN_ID, &tx, &witness).unwrap();
        // Áp dụng lại chính nó lên root mới: witness cũ không còn khớp.
        assert!(apply_transaction(root1, CHAIN_ID, &tx, &witness).is_err());
    }

    #[test]
    fn insufficient_balance_and_bad_nonce_rejected() {
        let (tree, root0, alice_id, alice) = alice_tree();
        let bob_id = [9u8; 32];
        let witness = |tree: &TestTree| TxWitness {
            from_state: AccountState {
                nonce: 0,
                balance: 1000,
            },
            from_proof: tree.proof(&alice_id),
            to_state: AccountState::EMPTY,
            to_proof: tree.proof(&bob_id),
        };

        let too_much = make_signed_transfer(&alice, CHAIN_ID, bob_id, 1001, 0);
        assert_eq!(
            apply_transaction(root0, CHAIN_ID, &too_much, &witness(&tree)),
            Err(TxError::InsufficientBalance)
        );

        let wrong_nonce = make_signed_transfer(&alice, CHAIN_ID, bob_id, 1, 5);
        assert_eq!(
            apply_transaction(root0, CHAIN_ID, &wrong_nonce, &witness(&tree)),
            Err(TxError::BadNonce {
                expected: 0,
                got: 5
            })
        );
    }

    #[test]
    fn attacker_cannot_spend_another_accounts_leaf() {
        // Mallory trình witness (state + proof) của Alice dưới tên mình: bị từ chối
        // vì lá của Alice gắn với account_id của Alice.
        let (tree, root0, alice_id, _alice) = alice_tree();
        let mallory = key(2);
        let tx = make_signed_transfer(&mallory, CHAIN_ID, [9u8; 32], 500, 0);

        let witness = TxWitness {
            from_state: AccountState {
                nonce: 0,
                balance: 1000,
            },
            from_proof: tree.proof(&alice_id),
            to_state: AccountState::EMPTY,
            to_proof: smt::empty_proof(),
        };
        assert_eq!(
            apply_transaction(root0, CHAIN_ID, &tx, &witness),
            Err(TxError::Merkle(SmtError::ProofMismatch))
        );
    }
}
