//! Unit test cho pallet — TRƯỚC ĐÂY PALLET KHÔNG CÓ TEST NÀO (kiểm tra
//! bằng cách đọc toàn bộ `src/lib.rs` gốc, không có `#[cfg(test)] mod
//! tests` nào cả). Ưu tiên test đúng những nhánh bảo mật mà 2 vòng vá đã
//! sửa (xem `L2_HUONG_DAN.md`): fail-closed sequencer, anti-replay,
//! weight refund, và phần Data Availability mới thêm.

#![cfg(test)]

use crate::mock::*;
use crate::{
    AuthorizedSequencer, BatchCount, BatchTransactionData, CurrentL2StateRoot, Error, Event,
    Risc0MethodId, RollupStateCommitment, Sp1VerificationKey, COMMITMENT_VERSION, EMPTY_STATE_ROOT,
};
use frame_support::{assert_noop, assert_ok, dispatch::DispatchResultWithPostInfo, BoundedVec};
use parity_scale_codec::Decode;
use sp_runtime::DispatchError;

/// `submit_l2_batch` trả `DispatchResultWithPostInfo` và các nhánh từ chối kèm
/// `actual_weight` (refund). `assert_noop!` so sánh nguyên cả `PostInfo` với giá
/// trị mặc định nên luôn lệch; helper này chỉ so phần `error`.
fn assert_rejected(result: DispatchResultWithPostInfo, expected: Error<Test>) {
    let expected: DispatchError = expected.into();
    assert_eq!(result.unwrap_err().error, expected);
}

fn valid_proof() -> BoundedVec<u8, TestMaxProofSize> {
    b"VALID".to_vec().try_into().unwrap()
}

fn setup_keys_and_sequencer(sequencer: AccountId) {
    let vkey: BoundedVec<u8, TestMaxVerificationKeySize> =
        b"fake-vkey".to_vec().try_into().unwrap();
    Sp1VerificationKey::<Test>::put(vkey);
    Risc0MethodId::<Test>::put([7u8; 32]);
    AuthorizedSequencer::<Test>::put(sequencer);
}

// ==================== Fail-closed sequencer (vá vòng 2, mục 1) ====================

#[test]
fn submit_fails_when_sequencer_not_set() {
    new_test_ext().execute_with(|| {
        // CỐ Ý không gọi setup_keys_and_sequencer — AuthorizedSequencer
        // vẫn là None, đúng trạng thái ngay sau bootstrap.
        assert_rejected(
            ZkRollupVerifier::submit_l2_batch(
                RuntimeOrigin::signed(1),
                [0u8; 32],
                [1u8; 32],
                valid_proof(),
                valid_proof(),
                Default::default(),
            ),
            Error::<Test>::SequencerNotSet,
        );
    });
}

#[test]
fn submit_fails_for_non_sequencer_account() {
    new_test_ext().execute_with(|| {
        setup_keys_and_sequencer(1); // account 1 là sequencer hợp lệ
        CurrentL2StateRoot::<Test>::put([0u8; 32]);

        assert_rejected(
            ZkRollupVerifier::submit_l2_batch(
                RuntimeOrigin::signed(2), // account 2 KHÔNG phải sequencer
                [0u8; 32],
                [1u8; 32],
                valid_proof(),
                valid_proof(),
                Default::default(),
            ),
            Error::<Test>::NotAuthorizedSequencer,
        );
    });
}

// ==================== Anti-replay (vá vòng 2, mục 3&4) ====================

#[test]
fn batch_index_increments_and_prevents_stale_old_root_replay() {
    new_test_ext().execute_with(|| {
        setup_keys_and_sequencer(1);
        CurrentL2StateRoot::<Test>::put([0u8; 32]);

        // Batch 0: root 0 -> 1, hợp lệ.
        assert_ok!(ZkRollupVerifier::submit_l2_batch(
            RuntimeOrigin::signed(1),
            [0u8; 32],
            [1u8; 32],
            valid_proof(),
            valid_proof(),
            Default::default(),
        ));
        assert_eq!(BatchCount::<Test>::get(), 1);
        assert_eq!(CurrentL2StateRoot::<Test>::get(), [1u8; 32]);

        // Replay batch 0 y hệt (old_root=[0;32]) sau khi state đã sang [1;32]
        // — phải bị từ chối vì old_root không khớp state hiện tại nữa. Đây
        // chính là lớp bảo vệ "tính liên tục của state" (bước 2 trong
        // extrinsic), ĐỘC LẬP với batch_index trong commitment — even nếu
        // ai đó có 1 proof cũ hợp lệ về mặt chữ ký ZK, root check này vẫn
        // chặn được replay ở tầng application trước khi proof kịp được
        // verify lại.
        assert_rejected(
            ZkRollupVerifier::submit_l2_batch(
                RuntimeOrigin::signed(1),
                [0u8; 32], // old_root cũ, không còn khớp CurrentL2StateRoot
                [1u8; 32],
                valid_proof(),
                valid_proof(),
                Default::default(),
            ),
            Error::<Test>::InvalidOldStateRoot,
        );
    });
}

#[test]
fn empty_state_transition_rejected() {
    new_test_ext().execute_with(|| {
        setup_keys_and_sequencer(1);
        CurrentL2StateRoot::<Test>::put([5u8; 32]);

        assert_rejected(
            ZkRollupVerifier::submit_l2_batch(
                RuntimeOrigin::signed(1),
                [5u8; 32],
                [5u8; 32], // old == new
                valid_proof(),
                valid_proof(),
                Default::default(),
            ),
            Error::<Test>::EmptyStateTransition,
        );
    });
}

// ==================== Verifier fail paths ====================

#[test]
fn sp1_verification_failure_rejects_batch() {
    new_test_ext().execute_with(|| {
        setup_keys_and_sequencer(1);
        CurrentL2StateRoot::<Test>::put([0u8; 32]);

        let bad_sp1_proof: BoundedVec<u8, TestMaxProofSize> = Default::default(); // rỗng -> MockVerifier từ chối

        assert_rejected(
            ZkRollupVerifier::submit_l2_batch(
                RuntimeOrigin::signed(1),
                [0u8; 32],
                [1u8; 32],
                bad_sp1_proof,
                valid_proof(),
                Default::default(),
            ),
            Error::<Test>::Sp1ProofVerificationFailed,
        );

        // State KHÔNG được đổi khi verify fail.
        assert_eq!(CurrentL2StateRoot::<Test>::get(), [0u8; 32]);
    });
}

#[test]
fn risc0_verification_failure_rejects_batch_even_when_sp1_passes() {
    new_test_ext().execute_with(|| {
        setup_keys_and_sequencer(1);
        CurrentL2StateRoot::<Test>::put([0u8; 32]);

        let bad_risc0_proof: BoundedVec<u8, TestMaxProofSize> = Default::default();

        assert_rejected(
            ZkRollupVerifier::submit_l2_batch(
                RuntimeOrigin::signed(1),
                [0u8; 32],
                [1u8; 32],
                valid_proof(),   // SP1 pass
                bad_risc0_proof, // Risc0 fail
                Default::default(),
            ),
            Error::<Test>::Risc0ProofVerificationFailed,
        );

        // Đúng thiết kế "chỉ cập nhật khi CẢ HAI hợp lệ" — SP1 pass không
        // đủ, state vẫn không đổi.
        assert_eq!(CurrentL2StateRoot::<Test>::get(), [0u8; 32]);
    });
}

// ==================== Data availability (việc mới thêm) ====================

#[test]
fn transaction_data_stored_and_retrievable() {
    new_test_ext().execute_with(|| {
        setup_keys_and_sequencer(1);
        CurrentL2StateRoot::<Test>::put([0u8; 32]);

        let data: BoundedVec<u8, TestMaxBatchDataSize> =
            b"fake tx blob".to_vec().try_into().unwrap();

        assert_ok!(ZkRollupVerifier::submit_l2_batch(
            RuntimeOrigin::signed(1),
            [0u8; 32],
            [1u8; 32],
            valid_proof(),
            valid_proof(),
            data.clone(),
        ));

        assert_eq!(BatchTransactionData::<Test>::get(0), Some(data));
    });
}

#[test]
fn old_batch_data_pruned_beyond_retention_window() {
    new_test_ext().execute_with(|| {
        setup_keys_and_sequencer(1);
        CurrentL2StateRoot::<Test>::put([0u8; 32]);

        // TestDataRetentionBatches = 3 (xem mock.rs) — submit 4 batch, batch
        // 0 phải bị dọn khi batch 3 được submit (batch_index=3, retention=3
        // => prune_index = 3 - 3 = 0).
        let mut root = [0u8; 32];
        for i in 0u8..4 {
            let new_root = [i + 1; 32];
            let data: BoundedVec<u8, TestMaxBatchDataSize> =
                // tests.rs chỉ compile dưới `#[cfg(test)]` (luôn có `std`),
                // nên `vec!` từ std prelude dùng thẳng được, không cần
                // `alloc::` hay `sp_std::` như benchmarking.rs (nơi có thể
                // bị compile vào WASM no_std runtime).
                vec![i].try_into().unwrap();

            assert_ok!(ZkRollupVerifier::submit_l2_batch(
                RuntimeOrigin::signed(1),
                root,
                new_root,
                valid_proof(),
                valid_proof(),
                data,
            ));
            root = new_root;
        }

        // Batch 0 đã bị dọn.
        assert_eq!(BatchTransactionData::<Test>::get(0), None);
        // Batch 1, 2, 3 vẫn còn (trong cửa sổ retention).
        assert!(BatchTransactionData::<Test>::get(1).is_some());
        assert!(BatchTransactionData::<Test>::get(2).is_some());
        assert!(BatchTransactionData::<Test>::get(3).is_some());
    });
}

// ==================== Admin extrinsics ====================

#[test]
fn only_root_can_set_sequencer() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ZkRollupVerifier::set_sequencer(RuntimeOrigin::signed(1), Some(1)),
            frame_support::error::BadOrigin
        );

        assert_ok!(ZkRollupVerifier::set_sequencer(
            RuntimeOrigin::root(),
            Some(1)
        ));
        assert_eq!(AuthorizedSequencer::<Test>::get(), Some(1));
    });
}

#[test]
fn setting_sequencer_to_none_closes_pallet_again() {
    new_test_ext().execute_with(|| {
        setup_keys_and_sequencer(1);
        assert_ok!(ZkRollupVerifier::set_sequencer(RuntimeOrigin::root(), None));

        CurrentL2StateRoot::<Test>::put([0u8; 32]);
        assert_rejected(
            ZkRollupVerifier::submit_l2_batch(
                RuntimeOrigin::signed(1),
                [0u8; 32],
                [1u8; 32],
                valid_proof(),
                valid_proof(),
                Default::default(),
            ),
            Error::<Test>::SequencerNotSet,
        );
    });
}

// ==================== Vá vòng 3: root khởi tạo, data_hash, weight ====================

#[test]
fn state_root_defaults_to_empty_tree_root() {
    new_test_ext().execute_with(|| {
        assert_eq!(CurrentL2StateRoot::<Test>::get(), EMPTY_STATE_ROOT);
    });
}

#[test]
fn empty_state_root_matches_formula() {
    // Cây rỗng độ sâu 256: EMPTY[0] = 32 byte 0, EMPTY[i] = SHA256(EMPTY[i-1] || EMPTY[i-1]).
    let mut h = [0u8; 32];
    for _ in 0..256 {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&h);
        buf[32..].copy_from_slice(&h);
        h = sp_io::hashing::sha2_256(&buf);
    }
    assert_eq!(h, EMPTY_STATE_ROOT);
}

#[test]
fn first_batch_is_accepted_from_default_root() {
    new_test_ext().execute_with(|| {
        setup_keys_and_sequencer(1);
        // KHÔNG đặt CurrentL2StateRoot: batch đầu tiên phải đi từ root cây rỗng.
        assert_ok!(ZkRollupVerifier::submit_l2_batch(
            RuntimeOrigin::signed(1),
            EMPTY_STATE_ROOT,
            [1u8; 32],
            valid_proof(),
            valid_proof(),
            Default::default(),
        ));
        assert_eq!(CurrentL2StateRoot::<Test>::get(), [1u8; 32]);
    });
}

#[test]
fn public_values_bind_data_hash_chain_id_and_batch_index() {
    new_test_ext().execute_with(|| {
        setup_keys_and_sequencer(1);
        let data: BoundedVec<u8, TestMaxBatchDataSize> = b"abc".to_vec().try_into().unwrap();

        assert_ok!(ZkRollupVerifier::submit_l2_batch(
            RuntimeOrigin::signed(1),
            EMPTY_STATE_ROOT,
            [1u8; 32],
            valid_proof(),
            valid_proof(),
            data,
        ));

        let public_values = LAST_PUBLIC_VALUES.with(|last| last.borrow().clone());
        let commitment = RollupStateCommitment::decode(&mut &public_values[..]).unwrap();
        assert_eq!(commitment.version, COMMITMENT_VERSION);
        assert_eq!(commitment.chain_id, 999); // TestChainId
        assert_eq!(commitment.batch_index, 0);
        assert_eq!(commitment.old_state_root, EMPTY_STATE_ROOT);
        assert_eq!(commitment.new_state_root, [1u8; 32]);
        assert_eq!(commitment.data_hash, sp_io::hashing::sha2_256(b"abc"));
    });
}

#[test]
fn different_data_gives_different_public_values() {
    new_test_ext().execute_with(|| {
        setup_keys_and_sequencer(1);
        let submit = |data: &[u8], old: [u8; 32], new: [u8; 32]| {
            let data: BoundedVec<u8, TestMaxBatchDataSize> = data.to_vec().try_into().unwrap();
            assert_ok!(ZkRollupVerifier::submit_l2_batch(
                RuntimeOrigin::signed(1),
                old,
                new,
                valid_proof(),
                valid_proof(),
                data,
            ));
            LAST_PUBLIC_VALUES.with(|last| last.borrow().clone())
        };
        let first = submit(b"one", EMPTY_STATE_ROOT, [1u8; 32]);
        let second = submit(b"two", [1u8; 32], [2u8; 32]);
        let c1 = RollupStateCommitment::decode(&mut &first[..]).unwrap();
        let c2 = RollupStateCommitment::decode(&mut &second[..]).unwrap();
        assert_ne!(c1.data_hash, c2.data_hash);
    });
}

#[test]
fn declared_weight_grows_with_data_length() {
    use crate::WeightInfo;
    let small = <() as WeightInfo>::data_write(0);
    let large = <() as WeightInfo>::data_write(512 * 1024);
    assert!(large.ref_time() > small.ref_time());
    assert_eq!(large.proof_size(), 512 * 1024);
}
