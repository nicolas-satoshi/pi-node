//! Sequencer tham chiếu: dựng witness và batch cho guest.
//!
//! Đây là phần NGOÀI chain mà trước đây chưa có: guest chỉ *verify* witness, còn ai
//! đó phải *tạo* chúng. Module này giữ cây trạng thái đầy đủ, nhận một danh sách
//! transaction đã ký, loại transaction không hợp lệ, và trả về đúng thứ nhà
//! prover cần (`RollupInput`) cùng blob DA để đăng lên L1.
//!
//! ## Phạm vi
//! - Đây là code tham chiếu cho test và cho sequencer thật tái sử dụng; KHÔNG phải
//!   dịch vụ mạng (không mempool, không RPC, không lưu đĩa).
//! - Cây được giữ trong bộ nhớ, mỗi `set` tốn 256 lần băm.
//!
//! ## Quy ước witness (khớp `transaction::TxWitness`)
//! proof của `from` lấy theo root HIỆN TẠI; proof của `to` lấy SAU KHI đã cập nhật
//! `from`.

use crate::smt::{self, AccountState, MerkleProof, TREE_DEPTH};
use crate::transaction::{self, SignedTransaction, TxError, TxWitness};
use crate::{RollupInput, COMMITMENT_VERSION};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use parity_scale_codec::Encode;
use sha2::{Digest, Sha256};

/// Khoá node: (độ sâu từ gốc, tiền tố đường đi đã che các bit sau độ sâu đó).
type NodeKey = (u16, [u8; 32]);

/// Giữ `depth` bit đầu của `path`, xoá phần còn lại.
fn prefix_of(path: &[u8; 32], depth: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    let full = depth / 8;
    out[..full].copy_from_slice(&path[..full]);
    let rem = depth % 8;
    if rem > 0 {
        out[full] = path[full] & (0xFFu8 << (8 - rem));
    }
    out
}

fn set_bit(prefix: &mut [u8; 32], i: usize) {
    prefix[i / 8] |= 1 << (7 - (i % 8));
}

/// Cây trạng thái L2 đầy đủ (thưa): chỉ lưu node khác node rỗng.
pub struct StateTree {
    nodes: BTreeMap<NodeKey, [u8; 32]>,
    accounts: BTreeMap<[u8; 32], AccountState>,
    /// `empties[h]` = hash cây rỗng cao `h`, h = 0..=TREE_DEPTH.
    empties: Vec<[u8; 32]>,
}

impl Default for StateTree {
    fn default() -> Self {
        Self::new()
    }
}

impl StateTree {
    pub fn new() -> Self {
        let mut empties = Vec::with_capacity(TREE_DEPTH + 1);
        let mut h = [0u8; 32];
        empties.push(h);
        for _ in 0..TREE_DEPTH {
            let mut hasher = Sha256::new();
            hasher.update(h);
            hasher.update(h);
            h = hasher.finalize().into();
            empties.push(h);
        }
        Self {
            nodes: BTreeMap::new(),
            accounts: BTreeMap::new(),
            empties,
        }
    }

    fn node(&self, depth: usize, prefix: [u8; 32]) -> [u8; 32] {
        self.nodes
            .get(&(depth as u16, prefix))
            .copied()
            .unwrap_or(self.empties[TREE_DEPTH - depth])
    }

    fn put(&mut self, depth: usize, prefix: [u8; 32], hash: [u8; 32]) {
        if hash == self.empties[TREE_DEPTH - depth] {
            self.nodes.remove(&(depth as u16, prefix));
        } else {
            self.nodes.insert((depth as u16, prefix), hash);
        }
    }

    /// Trạng thái hiện tại của account (`EMPTY` nếu chưa tồn tại).
    pub fn account(&self, id: &[u8; 32]) -> AccountState {
        self.accounts
            .get(id)
            .copied()
            .unwrap_or(AccountState::EMPTY)
    }

    pub fn root(&self) -> [u8; 32] {
        self.node(0, [0u8; 32])
    }

    /// Đặt trạng thái account và cập nhật các node trên đường lên gốc.
    /// Dùng cho genesis, nạp tiền (bridge sau này) và nội bộ `build_batch`.
    pub fn set_account(&mut self, id: &[u8; 32], state: AccountState) {
        if state == AccountState::EMPTY {
            self.accounts.remove(id);
        } else {
            self.accounts.insert(*id, state);
        }

        let path = smt::account_path(id);
        self.put(TREE_DEPTH, path, state.leaf_hash(id));

        for depth in (0..TREE_DEPTH).rev() {
            let left = prefix_of(&path, depth);
            let mut right = left;
            set_bit(&mut right, depth);

            let mut hasher = Sha256::new();
            hasher.update(self.node(depth + 1, left));
            hasher.update(self.node(depth + 1, right));
            let parent: [u8; 32] = hasher.finalize().into();
            self.put(depth, left, parent);
        }
    }

    /// Merkle proof của `id` theo cây hiện tại (kể cả account chưa tồn tại).
    pub fn proof(&self, id: &[u8; 32]) -> MerkleProof {
        let path = smt::account_path(id);
        let mut siblings = alloc::vec![[0u8; 32]; TREE_DEPTH];
        for r in 0..TREE_DEPTH {
            let mut key = prefix_of(&path, r);
            if smt::path_bit(&path, r) == 0 {
                set_bit(&mut key, r); // anh em nằm bên phải
            }
            // Nếu bit của path là 1, anh em nằm bên trái: bit r của khoá đã là 0.
            siblings[TREE_DEPTH - 1 - r] = self.node(r + 1, key);
        }
        MerkleProof { siblings }
    }
}

/// Kết quả dựng một batch.
pub struct BuiltBatch {
    /// Đưa nguyên cho prover (SP1/Risc0) làm private input.
    pub input: RollupInput,
    pub new_state_root: [u8; 32],
    /// `SCALE(Vec<SignedTransaction>)` — blob đăng lên L1 làm `transaction_data`.
    pub da_blob: Vec<u8>,
    /// `SHA256(da_blob)` — bằng `data_hash` trong public values.
    pub data_hash: [u8; 32],
    /// (vị trí trong danh sách đầu vào, lý do) của các tx bị loại.
    pub rejected: Vec<(usize, TxError)>,
}

impl StateTree {
    /// Dựng batch từ `candidates`. Tx không hợp lệ bị loại và KHÔNG làm đổi cây;
    /// tx hợp lệ được áp dụng theo thứ tự. Nếu không tx nào hợp lệ, batch rỗng
    /// vẫn hợp lệ (root không đổi).
    pub fn build_batch(
        &mut self,
        chain_id: u64,
        batch_index: u64,
        candidates: &[SignedTransaction],
    ) -> BuiltBatch {
        let old_state_root = self.root();
        let mut accepted: Vec<(SignedTransaction, TxWitness)> = Vec::new();
        let mut rejected: Vec<(usize, TxError)> = Vec::new();

        for (index, tx) in candidates.iter().enumerate() {
            match self.try_apply(chain_id, tx) {
                Ok(witness) => accepted.push((tx.clone(), witness)),
                Err(e) => rejected.push((index, e)),
            }
        }

        let only_txs: Vec<SignedTransaction> = accepted.iter().map(|(t, _)| t.clone()).collect();
        let da_blob = only_txs.encode();
        let data_hash: [u8; 32] = Sha256::digest(&da_blob).into();

        BuiltBatch {
            new_state_root: self.root(),
            input: RollupInput {
                chain_id,
                batch_index,
                old_state_root,
                transactions: accepted,
            },
            da_blob,
            data_hash,
            rejected,
        }
    }

    /// Kiểm tra và áp dụng một tx; lỗi thì cây được trả về đúng như cũ.
    fn try_apply(&mut self, chain_id: u64, tx: &SignedTransaction) -> Result<TxWitness, TxError> {
        if tx.from == tx.to {
            return Err(TxError::SelfTransfer);
        }
        transaction::verify_signature(tx, chain_id)?;

        let root_before = self.root();
        let from_state = self.account(&tx.from);
        if from_state.nonce != tx.nonce {
            return Err(TxError::BadNonce {
                expected: from_state.nonce,
                got: tx.nonce,
            });
        }
        let new_from = AccountState {
            nonce: from_state.nonce.checked_add(1).ok_or(TxError::Overflow)?,
            balance: from_state
                .balance
                .checked_sub(tx.amount)
                .ok_or(TxError::InsufficientBalance)?,
        };
        let to_state = self.account(&tx.to);
        let new_to = AccountState {
            nonce: to_state.nonce,
            balance: to_state
                .balance
                .checked_add(tx.amount)
                .ok_or(TxError::Overflow)?,
        };

        // Witness theo đúng thứ tự: from theo root cũ; to sau khi cập nhật from.
        let from_proof = self.proof(&tx.from);
        self.set_account(&tx.from, new_from);
        let to_proof = self.proof(&tx.to);
        let witness = TxWitness {
            from_state,
            from_proof,
            to_state,
            to_proof,
        };

        // Đối chiếu với đúng hàm mà guest sẽ chạy; sai lệch thì hoàn tác.
        match transaction::apply_transaction(root_before, chain_id, tx, &witness) {
            Ok(_) => {
                self.set_account(&tx.to, new_to);
                Ok(witness)
            }
            Err(e) => {
                self.set_account(&tx.from, from_state);
                Err(e)
            }
        }
    }
}

/// Public values mà một batch dựng bởi sequencer sẽ có, để so với output của guest.
pub fn expected_output(batch: &BuiltBatch) -> crate::RollupOutput {
    crate::RollupOutput {
        version: COMMITMENT_VERSION,
        chain_id: batch.input.chain_id,
        batch_index: batch.input.batch_index,
        old_state_root: batch.input.old_state_root,
        new_state_root: batch.new_state_root,
        data_hash: batch.data_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::TransferPayload;
    use crate::{execute_l2_state_transition, smt::EMPTY_STATE_ROOT};
    use ed25519_dalek::{Signer, SigningKey};
    use parity_scale_codec::Decode;

    const CHAIN_ID: u64 = 7;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn id_of(k: &SigningKey) -> [u8; 32] {
        k.verifying_key().to_bytes()
    }

    fn transfer(
        k: &SigningKey,
        chain_id: u64,
        to: [u8; 32],
        amount: u128,
        nonce: u64,
    ) -> SignedTransaction {
        let from = id_of(k);
        let payload = TransferPayload {
            chain_id,
            from,
            to,
            amount,
            nonce,
        };
        SignedTransaction {
            from,
            to,
            amount,
            nonce,
            signature: k.sign(&payload.encode()).to_bytes(),
        }
    }

    fn funded(k: &SigningKey, balance: u128) -> StateTree {
        let mut tree = StateTree::new();
        tree.set_account(&id_of(k), AccountState { nonce: 0, balance });
        tree
    }

    #[test]
    fn empty_tree_root_and_proofs_match_smt_module() {
        let tree = StateTree::new();
        assert_eq!(tree.root(), EMPTY_STATE_ROOT);
        assert_eq!(tree.proof(&[5u8; 32]).siblings, smt::empty_proof().siblings);
    }

    #[test]
    fn set_then_clear_returns_to_empty_root() {
        let mut tree = StateTree::new();
        let id = [3u8; 32];
        tree.set_account(
            &id,
            AccountState {
                nonce: 2,
                balance: 9,
            },
        );
        assert_ne!(tree.root(), EMPTY_STATE_ROOT);
        tree.set_account(&id, AccountState::EMPTY);
        assert_eq!(tree.root(), EMPTY_STATE_ROOT);
    }

    #[test]
    fn root_does_not_depend_on_insertion_order() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let sa = AccountState {
            nonce: 1,
            balance: 10,
        };
        let sb = AccountState {
            nonce: 0,
            balance: 20,
        };
        let mut t1 = StateTree::new();
        t1.set_account(&a, sa);
        t1.set_account(&b, sb);
        let mut t2 = StateTree::new();
        t2.set_account(&b, sb);
        t2.set_account(&a, sa);
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn proofs_verify_against_the_smt_module() {
        let mut tree = StateTree::new();
        for seed in 1..=5u8 {
            tree.set_account(
                &[seed; 32],
                AccountState {
                    nonce: seed as u64,
                    balance: seed as u128 * 100,
                },
            );
        }
        let root = tree.root();
        for id in [[1u8; 32], [4u8; 32], [77u8; 32]] {
            let state = tree.account(&id);
            let rebuilt = smt::compute_root(&id, state.leaf_hash(&id), &tree.proof(&id)).unwrap();
            assert_eq!(rebuilt, root);
        }
    }

    #[test]
    fn built_batch_is_accepted_by_guest_and_matches_everything() {
        let alice = key(1);
        let bob = key(2);
        let carol = [9u8; 32];
        let mut tree = funded(&alice, 1_000);
        tree.set_account(
            &id_of(&bob),
            AccountState {
                nonce: 0,
                balance: 50,
            },
        );

        let txs = alloc::vec![
            transfer(&alice, CHAIN_ID, id_of(&bob), 100, 0),
            transfer(&alice, CHAIN_ID, carol, 200, 1),
            transfer(&bob, CHAIN_ID, carol, 120, 0),
        ];
        let built = tree.build_batch(CHAIN_ID, 0, &txs);
        assert!(built.rejected.is_empty());
        assert_eq!(built.input.transactions.len(), 3);

        // Guest chạy trên input này phải ra đúng public values mà sequencer dự kiến.
        let out = execute_l2_state_transition(RollupInput {
            chain_id: built.input.chain_id,
            batch_index: built.input.batch_index,
            old_state_root: built.input.old_state_root,
            transactions: built.input.transactions.clone(),
        });
        assert_eq!(out, expected_output(&built));
        assert_eq!(out.new_state_root, tree.root());

        // data_hash là SHA-256 của đúng blob DA sẽ đăng lên L1.
        let digest: [u8; 32] = Sha256::digest(&built.da_blob).into();
        assert_eq!(built.data_hash, digest);

        // Số dư cuối đúng.
        assert_eq!(
            tree.account(&id_of(&alice)),
            AccountState {
                nonce: 2,
                balance: 700
            }
        );
        assert_eq!(
            tree.account(&id_of(&bob)),
            AccountState {
                nonce: 1,
                balance: 30
            }
        );
        assert_eq!(
            tree.account(&carol),
            AccountState {
                nonce: 0,
                balance: 320
            }
        );

        // Dựng lại cây từ số dư cuối cho cùng root (độc lập với đường áp dụng tx).
        let mut fresh = StateTree::new();
        fresh.set_account(&id_of(&alice), tree.account(&id_of(&alice)));
        fresh.set_account(&id_of(&bob), tree.account(&id_of(&bob)));
        fresh.set_account(&carol, tree.account(&carol));
        assert_eq!(fresh.root(), built.new_state_root);
    }

    #[test]
    fn invalid_transactions_are_dropped_without_touching_the_tree() {
        let alice = key(1);
        let mallory = key(3);
        let bob = [9u8; 32];
        let mut tree = funded(&alice, 1_000);

        let good1 = transfer(&alice, CHAIN_ID, bob, 100, 0);
        let bad_nonce = transfer(&alice, CHAIN_ID, bob, 1, 5);
        let too_much = transfer(&alice, CHAIN_ID, bob, 10_000, 1);
        let wrong_chain = transfer(&alice, CHAIN_ID + 1, bob, 1, 1);
        let self_tx = transfer(&alice, CHAIN_ID, id_of(&alice), 1, 1);
        let unfunded = transfer(&mallory, CHAIN_ID, bob, 1, 0);
        let good2 = transfer(&alice, CHAIN_ID, bob, 50, 1);

        let txs = alloc::vec![
            good1,
            bad_nonce,
            too_much,
            wrong_chain,
            self_tx,
            unfunded,
            good2
        ];
        let built = tree.build_batch(CHAIN_ID, 3, &txs);

        let rejected: Vec<usize> = built.rejected.iter().map(|(i, _)| *i).collect();
        assert_eq!(rejected, alloc::vec![1, 2, 3, 4, 5]);
        assert_eq!(built.input.transactions.len(), 2);
        assert_eq!(built.input.batch_index, 3);

        // Chỉ tx hợp lệ nằm trong blob DA.
        let in_blob = Vec::<SignedTransaction>::decode(&mut &built.da_blob[..]).unwrap();
        assert_eq!(in_blob.len(), 2);
        assert_eq!(in_blob[0].amount, 100);
        assert_eq!(in_blob[1].amount, 50);

        // Guest chấp nhận batch đã lọc và ra cùng root với cây của sequencer.
        let out = execute_l2_state_transition(RollupInput {
            chain_id: built.input.chain_id,
            batch_index: built.input.batch_index,
            old_state_root: built.input.old_state_root,
            transactions: built.input.transactions.clone(),
        });
        assert_eq!(out.new_state_root, tree.root());
        assert_eq!(
            tree.account(&id_of(&alice)),
            AccountState {
                nonce: 2,
                balance: 850
            }
        );
    }

    #[test]
    fn recipient_overflow_is_rejected_and_rolled_back() {
        let alice = key(1);
        let bob = [9u8; 32];
        let mut tree = funded(&alice, 10);
        tree.set_account(
            &bob,
            AccountState {
                nonce: 0,
                balance: u128::MAX,
            },
        );
        let before = tree.root();

        let built = tree.build_batch(CHAIN_ID, 0, &[transfer(&alice, CHAIN_ID, bob, 1, 0)]);
        assert_eq!(built.rejected.len(), 1);
        assert_eq!(built.rejected[0].1, TxError::Overflow);
        assert_eq!(tree.root(), before);
        assert_eq!(built.new_state_root, before);
    }

    #[test]
    fn empty_batch_keeps_root_and_is_valid_for_guest() {
        let alice = key(1);
        let mut tree = funded(&alice, 10);
        let built = tree.build_batch(CHAIN_ID, 0, &[]);
        assert_eq!(built.new_state_root, built.input.old_state_root);
        let out = execute_l2_state_transition(RollupInput {
            chain_id: built.input.chain_id,
            batch_index: built.input.batch_index,
            old_state_root: built.input.old_state_root,
            transactions: built.input.transactions.clone(),
        });
        assert_eq!(out, expected_output(&built));
    }

    #[test]
    fn batches_chain_root_to_root() {
        let alice = key(1);
        let bob = [9u8; 32];
        let mut tree = funded(&alice, 1_000);

        let b0 = tree.build_batch(CHAIN_ID, 0, &[transfer(&alice, CHAIN_ID, bob, 100, 0)]);
        let b1 = tree.build_batch(CHAIN_ID, 1, &[transfer(&alice, CHAIN_ID, bob, 100, 1)]);
        assert_eq!(b1.input.old_state_root, b0.new_state_root);
        assert_ne!(b1.new_state_root, b0.new_state_root);
    }
}
