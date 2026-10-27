//! Host function xác thực ZK proof — chạy Groth16 verify THẬT trong native
//! code của client (`bin/node`), KHÔNG chạy trong WASM runtime.
//!
//! ## Vì sao host function, không phải verify thẳng trong WASM
//!
//! `L2_HUONG_DAN.md` mục "Cắm verifier thật" gợi ý 2 cách: viết verifier
//! Groth16 `no_std` để chạy trong WASM, hoặc đưa việc verify ra host
//! function. Tôi chọn **host function** vì lý do cụ thể:
//!
//! 1. **An toàn hơn.** Native code dùng thẳng crate verifier `std` chính
//!    thức của SP1 (`sp1-sdk`) và Risc0 (`risc0-zkvm`) — đã được team gốc
//!    audit, maintain, update khi có lỗ hổng. Tự biên dịch pairing crypto
//!    (BN254/BLS12-381) sang `no_std`/WASM là tự ý implement lại phần khó
//!    nhất, dễ sai nhất của toàn bộ hệ verifier — sai một bit trong field
//!    arithmetic có thể khiến verifier "pass" một proof giả mà không ai
//!    phát hiện ra cho tới khi mất tiền thật.
//! 2. **`sp_runtime_interface` là cơ chế CHUẨN của Substrate** cho việc
//!    này — `sp_io::hashing::*`, `sp_io::crypto::*` đều là host function,
//!    không phải điều gì lạ hay hack.
//!
//! ## Đánh đổi cần biết
//!
//! - Node chạy dạng full-node KHÔNG dùng WASM executor cho phần verify này
//!   (native code chạy trực tiếp) — nghĩa là **light client / WASM-only
//!   executor không tự verify lại được** phần ZK, phải tin native host.
//!   Đây là giới hạn CHUNG của mọi host function trong Substrate, không
//!   riêng gì ở đây.
//! - Mọi validator PHẢI chạy đúng bản binary có host function này biên
//!   dịch đúng — không thể "chỉ cần đúng WASM runtime" như các pallet
//!   logic thông thường. Runtime upgrade qua sudo (`system.setCode`) sẽ
//!   KHÔNG tự cập nhật được phần verify này; phải nâng cấp binary node.
//!
//! LƯU Ý FILE NÀY LÀ MODULE CON của crate `primitives` (khai báo qua
//! `pub mod zk_host;` trong `primitives/src/lib.rs`), KHÔNG PHẢI crate
//! riêng — không được có `#![no_std]` ở đây, thuộc tính đó chỉ hợp lệ ở
//! gốc crate. `no_std` của toàn crate `primitives` (khai ở lib.rs) đã áp
//! dụng cho module này rồi.

use sp_runtime_interface::runtime_interface;

/// Kích thước tối đa hợp lý cho 1 tham số truyền qua FFI host function —
/// khớp `MaxProofSize`/`MaxVerificationKeySize` bên pallet (64 KiB / 16 KiB)
/// để không có 2 giới hạn khác nhau cho cùng một khái niệm.
pub const MAX_PROOF_BYTES: usize = 64 * 1024;
pub const MAX_VK_BYTES: usize = 16 * 1024;

#[runtime_interface]
pub trait ZkHostVerify {
    /// Verify Groth16 proof của SP1. Chạy NATIVE — implementation thật nằm
    /// trong nhánh `#[cfg(feature = "std")]` bên dưới, dùng thẳng
    /// `sp1-sdk`. Nhánh còn lại (không có `std`) là extern declaration tự
    /// sinh bởi macro `#[runtime_interface]`, runtime WASM gọi vào đây và
    /// FFI chuyển sang phía host thực thi.
    fn verify_sp1(proof: &[u8], vk: &[u8], public_values: &[u8]) -> bool {
        verify_sp1_native(proof, vk, public_values)
    }

    /// Verify proof của Risc0. Risc0 thường expose ra ngoài dưới dạng proof
    /// đã "wrap" thành Groth16 (để verify rẻ) — `risc0-zkvm` crate có sẵn
    /// hàm verify cho định dạng này ở phía host (native).
    fn verify_risc0(proof: &[u8], method_id: &[u8], public_values: &[u8]) -> bool {
        verify_risc0_native(proof, method_id, public_values)
    }
}

#[cfg(feature = "std")]
fn verify_sp1_native(proof: &[u8], vk: &[u8], public_values: &[u8]) -> bool {
    if proof.len() > MAX_PROOF_BYTES || vk.len() > MAX_VK_BYTES {
        return false;
    }

    // ⚠️ CHỖ NÀY CẦN BẠN ĐIỀN — tôi không có mạng để tra chính xác API
    // hiện tại của `sp1-sdk`/`sp1-verifier` (tên hàm, chữ ký tham số đổi
    // giữa các bản). Khung sườn dưới đây đúng Ý TƯỞNG (dùng thẳng verifier
    // std chính thức, không tự chế), nhưng bạn PHẢI đối chiếu với đúng bản
    // `sp1-zkvm`/`sp1-sdk` mình pin trước khi build:
    //
    //   use sp1_sdk::{ProverClient, SP1VerifyingKey, SP1Proof};
    //   let vk: SP1VerifyingKey = bincode::deserialize(vk).ok()?;
    //   let proof: SP1Proof = bincode::deserialize(proof).ok()?;
    //   // Kiểm public_values khớp trước khi verify — SP1 verify tự kiểm
    //   // public values nằm trong receipt, nhưng vẫn nên so khớp tường
    //   // minh với `public_values` truyền vào để chắc chắn không có lệch
    //   // lúc deserialize.
    //   ProverClient::new().verify(&proof, &vk).is_ok()
    //
    // Cho tới khi điền xong, hàm này PHẢI trả `false` — fail-closed, giống
    // hệt tinh thần `RejectAllVerifier` đã có trong pallet. TUYỆT ĐỐI
    // không để hàm này trả `true` mặc định "để test cho nhanh" rồi quên
    // sửa lại — đó chính là kiểu lỗi khiến `DevInsecureVerifier` phải tồn
    // tại như một cảnh báo riêng trong pallet.
    let _ = (proof, vk, public_values);
    // FAIL-CLOSED, KHÔNG panic. Bản trước dùng `unimplemented!()`: host function này
    // chạy trong quá trình xây/nhập block, nên một panic ở đây làm sập chính tiến
    // trình validator — sequencer gửi một batch là đủ kéo node xuống. Trả `false`
    // thì pallet chỉ từ chối batch (`Sp1ProofVerificationFailed`) và chain vẫn chạy.
    // TUYỆT ĐỐI không đổi thành `true`.
    false
}

#[cfg(feature = "std")]
fn verify_risc0_native(proof: &[u8], method_id: &[u8], public_values: &[u8]) -> bool {
    if proof.len() > MAX_PROOF_BYTES || method_id.len() != 32 {
        return false;
    }

    // ⚠️ Tương tự verify_sp1_native — khung sườn đúng ý tưởng, cần đối
    // chiếu API thật của `risc0-zkvm` bản đã pin:
    //
    //   use risc0_zkvm::{Receipt, InnerReceipt};
    //   let receipt: Receipt = bincode::deserialize(proof).ok()?;
    //   let image_id: [u8; 32] = method_id.try_into().ok()?;
    //   // receipt.journal chứa public_values đã commit — so khớp trước
    //   // khi verify, không chỉ tin verify() không panic:
    //   if receipt.journal.bytes != public_values { return false; }
    //   receipt.verify(image_id).is_ok()
    let _ = (proof, method_id, public_values);
    // Fail-closed, xem ghi chú ở `verify_sp1_native`.
    false
}

#[cfg(not(feature = "std"))]
fn verify_sp1_native(_proof: &[u8], _vk: &[u8], _public_values: &[u8]) -> bool {
    // Phía WASM không bao giờ chạy hàm này (macro `runtime_interface` chuyển lời gọi
    // sang host); trả `false` thay vì panic cho chắc.
    false
}

#[cfg(not(feature = "std"))]
fn verify_risc0_native(_proof: &[u8], _method_id: &[u8], _public_values: &[u8]) -> bool {
    false
}
