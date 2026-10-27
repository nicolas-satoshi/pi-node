//! Cắm host function `zk_host_verify` (xem `primitives/zk_host.rs`) vào
//! trait `ZkVerifier` mà pallet `zk-rollup-verifier` yêu cầu.
//!
//! Thay 2 dòng trong `bin/runtime/src/lib.rs`:
//!
//! ```rust,ignore
//! // TRƯỚC (bản HUONG_DAN.md gốc — dummy verifier):
//! #[cfg(not(feature = "zk-dev-insecure"))]
//! type ZkSp1Verifier = pallet_zk_rollup_verifier::RejectAllVerifier;
//! type ZkRisc0Verifier = pallet_zk_rollup_verifier::RejectAllVerifier;
//!
//! // SAU (bản này — host function thật, vẫn fail-closed cho tới khi bạn
//! // điền API sp1-sdk/risc0-zkvm thật vào primitives/zk_host.rs):
//! type ZkSp1Verifier = HostSp1Verifier;
//! type ZkRisc0Verifier = HostRisc0Verifier;
//! ```
//!
//! `dev-insecure-verifier` GIỮ NGUYÊN không đổi — vẫn cần cho việc test
//! đường ống submit-batch mà không cần proof thật, và vẫn bị khoá sau
//! `compile_error!` yêu cầu `i-understand-this-is-insecure` như cũ.

use pallet_zk_rollup_verifier::ZkVerifier;
// Đã khai `pub mod zk_host;` trong `primitives/src/lib.rs` — đường dẫn này
// đã cố định, không còn là placeholder cần bạn tự quyết định vị trí nữa.
use primitives::zk_host;

pub struct HostSp1Verifier;

impl ZkVerifier for HostSp1Verifier {
    fn verify(proof: &[u8], vk: &[u8], public_values: &[u8]) -> bool {
        // Gọi qua FFI host function — hàm `verify_sp1` tự sinh bởi macro
        // `#[runtime_interface]` trong zk_host.rs. Khi chạy trong runtime
        // WASM, lời gọi này rẽ sang thực thi ở native host (client); không
        // có logic verify nào chạy trong WASM cả.
        zk_host::verify_sp1(proof, vk, public_values)
    }
}

pub struct HostRisc0Verifier;

impl ZkVerifier for HostRisc0Verifier {
    fn verify(proof: &[u8], method_id: &[u8], public_values: &[u8]) -> bool {
        zk_host::verify_risc0(proof, method_id, public_values)
    }
}

// ============================================================================
// Việc CẦN LÀM TRƯỚC KHI BUILD:
// ============================================================================
//
// ĐÃ LÀM SẴN (áp trực tiếp vào repo, không cần bạn tự thêm nữa):
// - `pub mod zk_host;` trong `primitives/src/lib.rs`
// - `sp-runtime-interface = { workspace = true }` trong `primitives/Cargo.toml`
// - `mod zk_verifier_host_wiring;` (feature-gated `zk-host-verifier`) trong
//   `bin/runtime/src/lib.rs`
// - Feature `zk-host-verifier` trong `bin/runtime/Cargo.toml`
// - `ZkSp1Verifier`/`ZkRisc0Verifier` type alias chọn theo feature, trong
//   khối `impl pallet_zk_rollup_verifier::Config for Runtime`
//
// CÒN LẠI — CẦN BẠN TỰ LÀM (không tự động hoá được từ đây):
//
// 1. Điền API thật của sp1-sdk/risc0-zkvm vào 2 hàm
//    `verify_sp1_native`/`verify_risc0_native` trong
//    `primitives/src/zk_host.rs` — hiện tại hai hàm này trả `false`
//    (fail-closed: mọi proof bị từ chối). Bản trước dùng `unimplemented!()`
//    nên sequencer gửi một batch là làm panic cả validator; đã bỏ.
//    Lưu ý: kết quả của host function phải GIỐNG HỆT trên mọi validator —
//    mọi node phải chạy cùng phiên bản `sp1-sdk`/`risc0-zkvm`, nếu không
//    chain có thể tách nhánh.
//
// 2. `bin/node` (client, không phải runtime) cần link đúng crate
//    `sp1-sdk`/`risc0-zkvm` bản `std` — vì phần verify THẬT chạy ở đây,
//    không phải trong `bin/runtime`. Thêm vào `bin/node/Cargo.toml`, chỉ
//    khi feature `zk-host-verifier` bật (tránh kéo dependency nặng vào
//    build không cần).
//
// 3. Benchmark lại `submit_l2_batch` SAU KHI điền verifier thật — xem
//    `pallets/zk-rollup-verifier/src/benchmarking.rs`, cần fixture proof
//    thật sinh từ đúng bản l2-guest hiện tại (STF Merkle tree mới, không
//    phải bản fold-hash cũ).

