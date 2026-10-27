//! Benchmark THẬT cho pallet `zk-rollup-verifier`, thay số 500ms/250ms/30µs
//! đang là "ƯỚC LƯỢNG THÔ" (nguyên văn comment trong `WeightInfo for ()`).
//!
//! ## Vấn đề đặc thù của benchmark cho ZK verifier — đọc trước khi chạy
//!
//! Không giống hầu hết extrinsic khác, KHÔNG thể tự sinh 1 proof hợp lệ
//! ngay bên trong vòng lặp benchmark — sinh 1 proof Groth16 thật (kể cả đã
//! có STARK từ trước, bước "wrap" cũng vậy) tốn từ vài giây tới vài phút,
//! chạy hàng trăm lần trong benchmark là không khả thi.
//!
//! **Giải pháp chuẩn** (dùng ở đây): build sẵn ĐÚNG MỘT proof hợp lệ off-chain
//! (bằng `l2-guest` build ra + prover thật chạy 1 lần), nhúng cứng làm
//! fixture (`include_bytes!`), rồi benchmark dùng lại chính proof đó cho
//! mọi lần lặp. Verify thời gian không phụ thuộc *nội dung* proof (Groth16
//! verify là hằng thời gian với cùng 1 verification key/curve), nên dùng
//! lại 1 proof cố định vẫn cho số đo weight ĐÚNG cho trường hợp verify
//! thành công.
//!
//! ⚠️ **Fixture phải sinh LẠI mỗi khi guest program đổi** (thay đổi logic
//! STF, đổi phiên bản `sp1-zkvm`/`risc0-zkvm`) — vì proof gắn chặt với
//! image_id/method_id của đúng bản ELF đó. Không cắm nhầm fixture cũ vào
//! guest mới; verify sẽ luôn fail và benchmark đo sai (đo nhánh lỗi thay
//! vì nhánh thành công).

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::v2::*;
use frame_support::BoundedVec;
use frame_system::RawOrigin;

/// Proof SP1 hợp lệ đã sinh sẵn off-chain, ứng với 1 batch cố định (xem
/// `benchmark-fixtures/README.md` — CHƯA có ở đây, bạn cần tự chạy 1 lần
/// `cargo prove build` + prover thật để tạo file này).
///
/// Tạm thời trỏ tới file rỗng — benchmark CHƯA chạy được cho tới khi bạn
/// cung cấp fixture thật. Cố tình để trống thay vì giả một mảng byte ngẫu
/// nhiên, vì mảng giả sẽ khiến `cargo bench` chạy "được" nhưng đo sai hoàn
/// toàn (luôn rơi vào nhánh verify-fail, cho ra con số nhỏ giả tạo).
const FIXTURE_SP1_PROOF: &[u8] = &[]; // TODO: include_bytes!("../benchmark-fixtures/sp1_proof.bin")
const FIXTURE_SP1_VKEY: &[u8] = &[]; // TODO: include_bytes!("../benchmark-fixtures/sp1_vkey.bin")
const FIXTURE_RISC0_PROOF: &[u8] = &[]; // TODO: include_bytes!("../benchmark-fixtures/risc0_proof.bin")
const FIXTURE_RISC0_METHOD_ID: [u8; 32] = [0u8; 32]; // TODO: điền method_id thật
                                                     // (public_values gồm cả `data_hash` = SHA-256 của `transaction_data` — fixture phải sinh với đúng blob đó)
const FIXTURE_OLD_ROOT: [u8; 32] = [0u8; 32]; // TODO: khớp public_values trong fixture proof
const FIXTURE_NEW_ROOT: [u8; 32] = [1u8; 32]; // TODO: khớp public_values trong fixture proof

fn assert_fixtures_present<T: Config>() {
    assert!(
        !FIXTURE_SP1_PROOF.is_empty(),
        "Chưa điền benchmark fixture — xem docstring đầu file. \
         Benchmark cho nhánh thành công KHÔNG chạy được nếu thiếu."
    );
}

#[benchmarks]
mod benchmarks {
    use super::*;

    /// Nhánh THÀNH CÔNG đầy đủ — verify cả SP1 lẫn Risc0, cập nhật state.
    /// Đây là con số PHẢI dùng cho `WeightInfo::submit_l2_batch()`, thay
    /// 500ms ước lượng cũ.
    #[benchmark]
    fn submit_l2_batch() -> Result<(), BenchmarkError> {
        assert_fixtures_present::<T>();

        let sequencer: T::AccountId = whitelisted_caller();
        AuthorizedSequencer::<T>::put(sequencer.clone());

        let vkey: BoundedVec<u8, T::MaxVerificationKeySize> = FIXTURE_SP1_VKEY
            .to_vec()
            .try_into()
            .map_err(|_| BenchmarkError::Stop("FIXTURE_SP1_VKEY vượt MaxVerificationKeySize"))?;
        Sp1VerificationKey::<T>::put(vkey);
        Risc0MethodId::<T>::put(FIXTURE_RISC0_METHOD_ID);

        CurrentL2StateRoot::<T>::put(FIXTURE_OLD_ROOT);
        // batch_index phải khớp 0 vì đây là batch đầu tiên trong benchmark
        // (BatchCount mặc định 0) — fixture PHẢI được sinh với batch_index=0
        // trong RollupInput ở phía guest.

        let sp1_proof: BoundedVec<u8, T::MaxProofSize> = FIXTURE_SP1_PROOF
            .to_vec()
            .try_into()
            .map_err(|_| BenchmarkError::Stop("FIXTURE_SP1_PROOF vượt MaxProofSize"))?;
        let risc0_proof: BoundedVec<u8, T::MaxProofSize> = FIXTURE_RISC0_PROOF
            .to_vec()
            .try_into()
            .map_err(|_| BenchmarkError::Stop("FIXTURE_RISC0_PROOF vượt MaxProofSize"))?;

        #[extrinsic_call]
        submit_l2_batch(
            RawOrigin::Signed(sequencer),
            FIXTURE_OLD_ROOT,
            FIXTURE_NEW_ROOT,
            sp1_proof,
            risc0_proof,
        );

        assert_eq!(CurrentL2StateRoot::<T>::get(), FIXTURE_NEW_ROOT);
        Ok(())
    }

    /// Nhánh bị loại ở kiểm tra RẺ — trước khi chạm tới verify. KHÔNG cần
    /// fixture proof thật, vì bị từ chối trước bước đó (đúng ý đồ weight
    /// refund trong pallet: `submit_l2_batch_rejected()`).
    #[benchmark]
    fn submit_l2_batch_rejected() -> Result<(), BenchmarkError> {
        let attacker: T::AccountId = whitelisted_caller();
        // CỐ Ý không set AuthorizedSequencer — rơi đúng nhánh SequencerNotSet,
        // là kiểm tra RẺ NHẤT (chạy trước cả kiểm tra người gửi có đúng
        // sequencer hay không).

        let empty_proof: BoundedVec<u8, T::MaxProofSize> = Default::default();

        #[block]
        {
            let _ = Pallet::<T>::submit_l2_batch(
                RawOrigin::Signed(attacker).into(),
                [0u8; 32],
                [1u8; 32],
                empty_proof.clone(),
                empty_proof,
            );
        }

        Ok(())
    }

    /// Nhánh: SP1 verify thành công, Risc0 verify THẤT BẠI. Cần fixture SP1
    /// hợp lệ + risc0 proof rỗng/sai cố ý — đo đúng chi phí "đã trả 1 lần
    /// verify Groth16, chưa trả lần 2".
    #[benchmark]
    fn submit_l2_batch_sp1_failed() -> Result<(), BenchmarkError> {
        assert_fixtures_present::<T>();

        let sequencer: T::AccountId = whitelisted_caller();
        AuthorizedSequencer::<T>::put(sequencer.clone());

        let vkey: BoundedVec<u8, T::MaxVerificationKeySize> = FIXTURE_SP1_VKEY
            .to_vec()
            .try_into()
            .map_err(|_| BenchmarkError::Stop("FIXTURE_SP1_VKEY vượt MaxVerificationKeySize"))?;
        Sp1VerificationKey::<T>::put(vkey);
        Risc0MethodId::<T>::put(FIXTURE_RISC0_METHOD_ID);
        CurrentL2StateRoot::<T>::put(FIXTURE_OLD_ROOT);

        let sp1_proof: BoundedVec<u8, T::MaxProofSize> = FIXTURE_SP1_PROOF
            .to_vec()
            .try_into()
            .map_err(|_| BenchmarkError::Stop("FIXTURE_SP1_PROOF vượt MaxProofSize"))?;

        // Risc0 proof CỐ Ý sai (1 byte khác 0, đủ để verifier thật từ chối,
        // nhưng vẫn "khác rỗng" để lọt qua nếu lỡ chạy với DevInsecureVerifier
        // trong môi trường benchmark thử nghiệm).
        let bad_risc0_proof: BoundedVec<u8, T::MaxProofSize> =
            sp_std::vec![0xFFu8; 32].try_into().unwrap();

        #[block]
        {
            let _ = Pallet::<T>::submit_l2_batch(
                RawOrigin::Signed(sequencer).into(),
                FIXTURE_OLD_ROOT,
                FIXTURE_NEW_ROOT,
                sp1_proof,
                bad_risc0_proof,
            );
        }

        Ok(())
    }

    #[benchmark]
    fn set_sp1_verification_key() -> Result<(), BenchmarkError> {
        let key: BoundedVec<u8, T::MaxVerificationKeySize> =
            sp_std::vec![0u8; T::MaxVerificationKeySize::get() as usize]
                .try_into()
                .unwrap();

        #[extrinsic_call]
        _(RawOrigin::Root, key);

        Ok(())
    }

    #[benchmark]
    fn set_risc0_method_id() -> Result<(), BenchmarkError> {
        #[extrinsic_call]
        _(RawOrigin::Root, [7u8; 32]);

        Ok(())
    }

    #[benchmark]
    fn set_sequencer() -> Result<(), BenchmarkError> {
        let account: T::AccountId = whitelisted_caller();

        #[extrinsic_call]
        _(RawOrigin::Root, Some(account));

        Ok(())
    }

    impl_benchmark_test_suite!(
        Pallet,
        crate::mock::new_test_ext(), // ⚠️ cần có sẵn mock runtime — xem ghi chú cuối file
        crate::mock::Test,
    );
}

// ============================================================================
// Việc CẦN LÀM TRƯỚC KHI CHẠY BENCHMARK THẬT:
// ============================================================================
//
// 1. Sinh fixture thật: build l2-guest, chạy prover 1 lần với 1 batch nhỏ
//    (1 transaction), lưu output làm 4 file trong `benchmark-fixtures/`.
//    Bỏ comment các dòng `include_bytes!` ở đầu file, xoá các hằng rỗng.
//
// 2. `pallets/zk-rollup-verifier` hiện KHÔNG có `mock.rs` (không thấy test
//    module nào khi đọc `src/lib.rs` ban đầu) — cần viết mock runtime tối
//    thiểu trước khi `impl_benchmark_test_suite!` compile được. Đây là việc
//    tách riêng, không có trong 5 việc gốc nhưng là điều kiện cần.
//
// 3. Chạy trên phần cứng THẬT giống production (không phải máy dev cá
//    nhân) — verify Groth16 tốn CPU đáng kể, số đo trên máy yếu/mạnh khác
//    nhau nhiều, và weight cuối cùng phải phản ánh máy validator kém nhất
//    được chấp nhận trong mạng, không phải máy nhanh nhất.
//
// 4. Sau khi có số thật, thay `impl WeightInfo for ()` (hard-code trong
//    pallet lib.rs) bằng weight file tự sinh
//    (`cargo build ... benchmark pallet ... --output weights.rs`).
