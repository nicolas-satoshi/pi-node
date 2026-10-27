//! Sparse Merkle Tree cho account state L2.
//!
//! ## Thiết kế
//! - Độ sâu cố định `TREE_DEPTH = 256`: đường đi của một account là TOÀN BỘ 256 bit
//!   của `SHA256(account_id)`. Hai account khác nhau không thể trùng ô một cách
//!   thực tế (va chạm SHA-256).
//!
//!   Bản trước dùng độ sâu 32 (chỉ 32 bit đầu của hash) và lá không chứa
//!   `account_id`: hai account trùng 32 bit dùng chung một ô, và Merkle proof của
//!   người này "khớp" với người kia. Tìm một khoá trùng ô với nạn nhân tốn cỡ 2^32
//!   lần thử — kẻ tấn công ký bằng khoá của mình để chi tiêu số dư của nạn nhân.
//! - Lá = `SHA256(LEAF_DOMAIN || account_id || SCALE(nonce, balance))`. Lá GẮN với
//!   account_id, nên proof của account này không dùng được cho account khác kể cả
//!   khi hai bên có cùng nonce/balance.
//! - Lá rỗng = 32 byte 0; `EMPTY[i] = SHA256(EMPTY[i-1] || EMPTY[i-1])`.
//!   Account có `(nonce 0, balance 0)` được coi là chưa tồn tại.
//!
//! ## Giới hạn cố ý
//! - Không có phí giao dịch và không có existential deposit.
//! - Witness do sequencer cung cấp; guest chỉ verify rồi cập nhật.

use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode};
use sha2::{Digest, Sha256};

pub const TREE_DEPTH: usize = 256;

/// Root của cây rỗng ở độ sâu 256. Pallet L1 dùng đúng giá trị này làm state
/// root khởi tạo (`DefaultStateRoot`). Test `empty_root_matches_constant` đảm
/// bảo hằng số khớp công thức; pallet có test riêng tính lại bằng `sp_io`.
pub const EMPTY_STATE_ROOT: [u8; 32] = [
    0xb1, 0x78, 0xc2, 0x45, 0xc9, 0x47, 0xea, 0x7e, 0x21, 0xec, 0xed, 0xe0, 0x77, 0x28, 0x94, 0x1a,
    0x6a, 0xb1, 0xb7, 0x06, 0x14, 0x3c, 0x06, 0x87, 0x3b, 0xaf, 0xf8, 0xeb, 0xd6, 0xde, 0x63, 0x08,
];

/// Domain separator cho hash của lá.
const LEAF_DOMAIN: &[u8] = b"pi-l2/leaf/v1";

/// Hash của cây rỗng có chiều cao `height` (0 = một lá rỗng).
pub fn empty_hash_at_height(height: usize) -> [u8; 32] {
    let mut h = [0u8; 32];
    for _ in 0..height {
        let mut hasher = Sha256::new();
        hasher.update(h);
        hasher.update(h);
        h = hasher.finalize().into();
    }
    h
}

/// Root của cây rỗng, tính từ công thức.
pub fn empty_root() -> [u8; 32] {
    empty_hash_at_height(TREE_DEPTH)
}

/// Merkle proof của một account trong cây rỗng: sibling ở tầng `d` (tính từ lá)
/// là cây rỗng cao `d`.
pub fn empty_proof() -> MerkleProof {
    MerkleProof {
        siblings: (0..TREE_DEPTH).map(empty_hash_at_height).collect(),
    }
}

/// Trạng thái một account trong cây.
#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, Debug)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: u128,
}

impl AccountState {
    pub const EMPTY: AccountState = AccountState {
        nonce: 0,
        balance: 0,
    };

    /// Giá trị lá của `account_id` với trạng thái này.
    pub fn leaf_hash(&self, account_id: &[u8; 32]) -> [u8; 32] {
        if *self == Self::EMPTY {
            return [0u8; 32];
        }
        let mut hasher = Sha256::new();
        hasher.update(LEAF_DOMAIN);
        hasher.update(account_id);
        hasher.update(self.encode());
        hasher.finalize().into()
    }
}

/// Merkle proof: hash của node anh em ở mỗi tầng.
#[derive(Encode, Decode, Clone)]
pub struct MerkleProof {
    /// Đúng `TREE_DEPTH` phần tử, từ lá lên gốc.
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SmtError {
    /// `siblings.len() != TREE_DEPTH`.
    BadProofLength,
    /// Proof không khớp root đã cho — account_state hoặc witness sai.
    ProofMismatch,
}

/// Đường đi của account trong cây: `SHA256(account_id)`, đọc từng bit từ MSB.
pub fn account_path(account_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(account_id);
    hasher.finalize().into()
}

/// Bit thứ `i` của đường đi (0 = bit gần gốc nhất).
pub fn path_bit(path: &[u8; 32], i: usize) -> u8 {
    (path[i / 8] >> (7 - (i % 8))) & 1
}

/// Tính lại root từ một lá và Merkle proof.
pub fn compute_root(
    account_id: &[u8; 32],
    leaf: [u8; 32],
    proof: &MerkleProof,
) -> Result<[u8; 32], SmtError> {
    if proof.siblings.len() != TREE_DEPTH {
        return Err(SmtError::BadProofLength);
    }

    let path = account_path(account_id);
    let mut current = leaf;

    // `depth` = số tầng tính từ lá; tầng gần lá nhất dùng bit cuối của đường đi.
    for depth in 0..TREE_DEPTH {
        let bit = path_bit(&path, TREE_DEPTH - 1 - depth);
        let sibling = proof.siblings[depth];

        let mut hasher = Sha256::new();
        if bit == 0 {
            hasher.update(current);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(current);
        }
        current = hasher.finalize().into();
    }

    Ok(current)
}

/// Verify `old_state` của `account_id` khớp `old_root` qua proof, rồi trả về root
/// mới sau khi thay lá bằng `new_state`.
pub fn apply_update(
    old_root: [u8; 32],
    account_id: &[u8; 32],
    old_state: AccountState,
    new_state: AccountState,
    proof: &MerkleProof,
) -> Result<[u8; 32], SmtError> {
    let computed_old_root = compute_root(account_id, old_state.leaf_hash(account_id), proof)?;
    if computed_old_root != old_root {
        return Err(SmtError::ProofMismatch);
    }

    compute_root(account_id, new_state.leaf_hash(account_id), proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_matches_constant() {
        assert_eq!(empty_root(), EMPTY_STATE_ROOT);
    }

    #[test]
    fn empty_proof_reproduces_empty_root() {
        let id = [7u8; 32];
        let root = compute_root(&id, AccountState::EMPTY.leaf_hash(&id), &empty_proof()).unwrap();
        assert_eq!(root, EMPTY_STATE_ROOT);
    }

    #[test]
    fn path_bit_reads_msb_first() {
        let mut path = [0u8; 32];
        path[0] = 0b1000_0000;
        path[31] = 0b0000_0001;
        assert_eq!(path_bit(&path, 0), 1);
        assert_eq!(path_bit(&path, 1), 0);
        assert_eq!(path_bit(&path, 255), 1);
        assert_eq!(path_bit(&path, 254), 0);
    }

    #[test]
    fn leaf_is_bound_to_account_id() {
        let state = AccountState {
            nonce: 1,
            balance: 1_000,
        };
        assert_ne!(state.leaf_hash(&[1u8; 32]), state.leaf_hash(&[2u8; 32]));
    }

    #[test]
    fn update_from_empty_tree_changes_root() {
        let id = [3u8; 32];
        let new_state = AccountState {
            nonce: 0,
            balance: 50,
        };
        let root = apply_update(
            EMPTY_STATE_ROOT,
            &id,
            AccountState::EMPTY,
            new_state,
            &empty_proof(),
        )
        .unwrap();
        assert_ne!(root, EMPTY_STATE_ROOT);
    }

    #[test]
    fn proof_of_one_account_does_not_verify_for_another() {
        // Cây có đúng một account A. Proof + state của A không được chấp nhận
        // khi trình ra dưới danh nghĩa account B có cùng state.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let state = AccountState {
            nonce: 4,
            balance: 900,
        };
        let proof = empty_proof();
        let root_with_a = compute_root(&a, state.leaf_hash(&a), &proof).unwrap();

        assert_eq!(
            apply_update(root_with_a, &b, state, AccountState::EMPTY, &proof),
            Err(SmtError::ProofMismatch)
        );
    }

    #[test]
    fn wrong_proof_length_rejected() {
        let id = [1u8; 32];
        let proof = MerkleProof {
            siblings: alloc::vec![[0u8; 32]; 32],
        };
        assert_eq!(
            compute_root(&id, [0u8; 32], &proof),
            Err(SmtError::BadProofLength)
        );
    }
}
