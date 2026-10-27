//! Logic L2 dùng chung cho guest zkVM (SP1/Risc0) và cho test/sequencer ngoài chain.
//!
//! Tách khỏi `main.rs` để chạy được `cargo test --features std --lib` mà không cần
//! toolchain zkVM. `main.rs` chỉ còn đọc input, gọi `execute_l2_state_transition`
//! rồi commit output.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod sequencer;
pub mod smt;
pub mod transaction;

use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode};
use transaction::{SignedTransaction, TxWitness};

/// Phải khớp `COMMITMENT_VERSION` trong pallet.
///
/// 3: thêm `data_hash` vào public values; cây Merkle 256 bit với `account_id`
/// trong lá; chữ ký giao dịch có `chain_id`. Proof theo layout cũ tự hết hiệu lực.
pub const COMMITMENT_VERSION: u8 = 3;

/// Đầu vào riêng tư (private witness) của batch.
#[derive(Encode, Decode, Clone)]
pub struct RollupInput {
    pub chain_id: u64,
    pub batch_index: u64,
    pub old_state_root: [u8; 32],
    pub transactions: Vec<(SignedTransaction, TxWitness)>,
}

/// Public values commit lên L1. Thứ tự field PHẢI khớp `RollupStateCommitment`
/// trong pallet (SCALE, byte-for-byte).
#[derive(Encode, Decode, Clone, PartialEq, Debug)]
pub struct RollupOutput {
    pub version: u8,
    pub chain_id: u64,
    pub batch_index: u64,
    pub old_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    /// SHA-256 của `SCALE(Vec<SignedTransaction>)` — chính là blob
    /// `transaction_data` mà sequencer đăng on-chain. Pallet tự băm blob nhận
    /// được và đối chiếu qua public values, nên dữ liệu DA không thể khác với
    /// những gì đã được chứng minh.
    pub data_hash: [u8; 32],
}

/// STF thật: verify chữ ký + nonce + số dư + Merkle proof cho MỖI transaction.
///
/// Panic (= không sinh được proof) nếu bất kỳ transaction nào không hợp lệ.
pub fn execute_l2_state_transition(input: RollupInput) -> RollupOutput {
    let new_state_root =
        transaction::apply_batch(input.old_state_root, input.chain_id, &input.transactions)
            .expect("transaction không hợp lệ trong batch — xem TxError để biết lý do");

    RollupOutput {
        version: COMMITMENT_VERSION,
        chain_id: input.chain_id,
        batch_index: input.batch_index,
        old_state_root: input.old_state_root,
        new_state_root,
        data_hash: transaction::batch_data_hash(&input.transactions),
    }
}
