//! Điểm vào cho zkVM (SP1 hoặc Risc0). Chỉ làm I/O; logic ở `lib.rs`.

#![no_main]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use l2_guest::{execute_l2_state_transition, RollupInput};
use parity_scale_codec::{Decode, Encode};

#[cfg(not(any(feature = "sp1", feature = "risc0")))]
compile_error!("Phải bật đúng một feature: --features sp1  HOẶC  --features risc0");

#[cfg(all(feature = "sp1", feature = "risc0"))]
compile_error!("Không bật đồng thời sp1 và risc0 — mỗi lần build một zkVM.");

#[cfg(feature = "sp1")]
sp1_zkvm::entrypoint!(main);

#[cfg(feature = "risc0")]
risc0_zkvm::guest::entry!(main);

pub fn main() {
    #[cfg(feature = "sp1")]
    let raw: Vec<u8> = sp1_zkvm::io::read_vec();

    #[cfg(feature = "risc0")]
    let raw: Vec<u8> = risc0_zkvm::guest::env::read();

    let input = RollupInput::decode(&mut &raw[..]).expect("input SCALE không hợp lệ");

    let output = execute_l2_state_transition(input);
    let encoded = output.encode();

    #[cfg(feature = "sp1")]
    sp1_zkvm::io::commit_slice(&encoded);

    #[cfg(feature = "risc0")]
    risc0_zkvm::guest::env::commit_slice(&encoded);
}
