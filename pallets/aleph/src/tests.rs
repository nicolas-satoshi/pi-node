use frame_support::{storage_alias, traits::OneSessionHandler};
use primitives::{VersionChange, HARD_SUPPLY_CAP, MIN_INFLATION_PARAMS_CHANGE_INTERVAL, TOKEN};
use sp_runtime::DispatchError;

use crate::{mock::*, AzeroCap, InflationParametersLastChange, NextFinalityCommittee};

#[storage_alias]
type SessionForValidatorsChange = StorageValue<Aleph, u32>;

#[storage_alias]
type Validators<T> = StorageValue<Aleph, Vec<<T as frame_system::Config>::AccountId>>;

#[test]
fn test_update_authorities() {
    new_test_ext(&[(1u64, 1u64), (2u64, 2u64)]).execute_with(|| {
        initialize_session();
        run_session(1);

        NextFinalityCommittee::<Test>::put(vec![2, 3, 4]);
        let authorities = [2, 3, 4].iter().zip(to_authorities(&[2, 3, 4])).collect();

        Aleph::update_authorities(authorities);

        assert_eq!(Aleph::authorities(), to_authorities(&[1, 2]));
        assert_eq!(Aleph::next_authorities(), to_authorities(&[2, 3, 4]));
    });
}

#[test]
fn test_initialize_authorities() {
    new_test_ext(&[(1u64, 1u64), (2u64, 2u64)]).execute_with(|| {
        assert_eq!(Aleph::authorities(), to_authorities(&[1, 2]));
        assert_eq!(Aleph::next_authorities(), to_authorities(&[1, 2]));
    });
}

#[test]
fn fails_to_initialize_again_authorities() {
    new_test_ext(&[(1u64, 1u64), (2u64, 2u64)]).execute_with(|| {
        let authorities = to_authorities(&[1, 2, 3]);
        Aleph::initialize_authorities(&authorities, &authorities);

        // should not update storage
        assert_eq!(Aleph::authorities(), to_authorities(&[1, 2]));
    });
}

#[test]
fn test_current_authorities() {
    new_test_ext(&[(1u64, 1u64), (2u64, 2u64)]).execute_with(|| {
        initialize_session();

        run_session(1);

        NextFinalityCommittee::<Test>::put(vec![2, 3, 4]);
        let authorities = [2, 3, 4].iter().zip(to_authorities(&[2, 3, 4])).collect();
        Aleph::update_authorities(authorities);

        assert_eq!(Aleph::authorities(), to_authorities(&[1, 2]));
        assert_eq!(Aleph::next_authorities(), to_authorities(&[2, 3, 4]));

        run_session(2);

        NextFinalityCommittee::<Test>::put(vec![1, 2, 3]);
        let authorities = [1, 2, 3].iter().zip(to_authorities(&[1, 2, 3])).collect();
        Aleph::update_authorities(authorities);

        assert_eq!(Aleph::authorities(), to_authorities(&[2, 3, 4]));
        assert_eq!(Aleph::next_authorities(), to_authorities(&[1, 2, 3]));
    })
}

#[test]
fn test_session_rotation() {
    new_test_ext(&[(1u64, 1u64), (2u64, 2u64)]).execute_with(|| {
        initialize_session();
        run_session(1);

        NextFinalityCommittee::<Test>::put(vec![5, 6]);
        let new_validators = new_session_validators(&[1, 2]);
        let queued_validators = new_session_validators(&[5, 6]);
        Aleph::on_new_session(true, new_validators, queued_validators);
        assert_eq!(Aleph::authorities(), to_authorities(&[1, 2]));
        assert_eq!(Aleph::next_authorities(), to_authorities(&[5, 6]));
    })
}

#[test]
fn test_session_rotation_with_larger_permuted_authorities() {
    new_test_ext(&[(1u64, 1u64), (2u64, 2u64)]).execute_with(|| {
        initialize_session();
        run_session(1);

        NextFinalityCommittee::<Test>::put(vec![5, 6]);
        let new_validators = new_session_validators(&[1, 2]);
        let queued_validators = new_session_validators(&[6, 4, 5]);
        Aleph::on_new_session(true, new_validators, queued_validators);
        assert_eq!(Aleph::authorities(), to_authorities(&[1, 2]));
        assert_eq!(Aleph::next_authorities(), to_authorities(&[5, 6]));
    })
}

#[test]
fn test_emergency_signer() {
    new_test_ext(&[(1u64, 1u64), (2u64, 2u64)]).execute_with(|| {
        initialize_session();

        run_session(1);

        Aleph::set_next_emergency_finalizer(to_authority(&21));

        assert_eq!(Aleph::emergency_finalizer(), None);
        assert_eq!(Aleph::queued_emergency_finalizer(), None);

        run_session(2);

        Aleph::set_next_emergency_finalizer(to_authority(&37));

        assert_eq!(Aleph::emergency_finalizer(), None);
        assert_eq!(Aleph::queued_emergency_finalizer(), Some(to_authority(&21)));

        run_session(3);

        assert_eq!(Aleph::emergency_finalizer(), Some(to_authority(&21)));
        assert_eq!(Aleph::queued_emergency_finalizer(), Some(to_authority(&37)));
    })
}

#[test]
fn test_finality_version_scheduling() {
    new_test_ext(&[(1u64, 1u64), (2u64, 2u64)]).execute_with(|| {
        initialize_session();

        run_session(1);

        let version_to_schedule = VersionChange {
            version_incoming: 1,
            session: 4,
        };

        let scheduling_result =
            Aleph::do_schedule_finality_version_change(version_to_schedule.clone());
        assert_eq!(scheduling_result, Ok(()));

        let scheduled_version_change = Aleph::finality_version_change();
        assert_eq!(scheduled_version_change, Some(version_to_schedule.clone()));

        run_session(4);

        let current_version = Aleph::finality_version();
        assert_eq!(current_version, version_to_schedule.version_incoming);

        let scheduled_version_change = Aleph::finality_version_change();
        assert_eq!(scheduled_version_change, None);

        let version_to_schedule = VersionChange {
            version_incoming: 1,
            session: 5,
        };

        let scheduling_result = Aleph::do_schedule_finality_version_change(version_to_schedule);
        assert!(scheduling_result.is_err());
    })
}

#[test]
fn inflation_cap_cannot_exceed_hard_supply_cap() {
    new_test_ext(&[(1u64, 1u64), (2u64, 2u64)]).execute_with(|| {
        let result =
            Aleph::set_inflation_parameters(RuntimeOrigin::root(), Some(HARD_SUPPLY_CAP + 1), None);

        // Biên theo từng lần gọi (gấp đôi khoảng cách) sẽ cho qua giá trị này;
        // chỉ trần tuyệt đối chặn được nó.
        assert_eq!(
            result,
            Err(DispatchError::Other(
                "AZERO Cap exceeds the hard supply cap compiled into the runtime!"
            ))
        );
        assert_eq!(AzeroCap::<Test>::get(), HARD_SUPPLY_CAP);
        assert_eq!(InflationParametersLastChange::<Test>::get(), None);
    });
}

#[test]
fn inflation_parameters_change_is_rate_limited() {
    new_test_ext(&[(1u64, 1u64), (2u64, 2u64)]).execute_with(|| {
        // Lần đầu: được phép ngay (hạ trần 28M -> 27M, nằm trong biên).
        assert_eq!(
            Aleph::set_inflation_parameters(RuntimeOrigin::root(), Some(27_000_000 * TOKEN), None),
            Ok(())
        );
        assert_eq!(AzeroCap::<Test>::get(), 27_000_000 * TOKEN);
        assert_eq!(InflationParametersLastChange::<Test>::get(), Some(0));

        // Lần hai ngay sau đó: bị từ chối, trần giữ nguyên.
        let too_soon_error = Err(DispatchError::Other(
            "Inflation parameters were changed too recently!",
        ));
        assert_eq!(
            Aleph::set_inflation_parameters(RuntimeOrigin::root(), Some(26_000_000 * TOKEN), None),
            too_soon_error
        );
        assert_eq!(AzeroCap::<Test>::get(), 27_000_000 * TOKEN);

        // Chưa đủ khoảng cách (thiếu 1 block): vẫn bị từ chối.
        System::set_block_number(MIN_INFLATION_PARAMS_CHANGE_INTERVAL as u64 - 1);
        assert_eq!(
            Aleph::set_inflation_parameters(RuntimeOrigin::root(), Some(26_000_000 * TOKEN), None),
            too_soon_error
        );

        // Đủ khoảng cách: được phép, và mốc thời gian được cập nhật.
        System::set_block_number(MIN_INFLATION_PARAMS_CHANGE_INTERVAL as u64);
        assert_eq!(
            Aleph::set_inflation_parameters(RuntimeOrigin::root(), Some(26_000_000 * TOKEN), None),
            Ok(())
        );
        assert_eq!(AzeroCap::<Test>::get(), 26_000_000 * TOKEN);
        assert_eq!(
            InflationParametersLastChange::<Test>::get(),
            Some(MIN_INFLATION_PARAMS_CHANGE_INTERVAL as u64)
        );
    });
}

#[test]
fn rejected_inflation_change_does_not_start_cooldown() {
    new_test_ext(&[(1u64, 1u64), (2u64, 2u64)]).execute_with(|| {
        assert!(Aleph::set_inflation_parameters(
            RuntimeOrigin::root(),
            Some(HARD_SUPPLY_CAP + 1),
            None
        )
        .is_err());
        // Lần gọi hợp lệ ngay sau đó vẫn được chấp nhận.
        assert_eq!(
            Aleph::set_inflation_parameters(RuntimeOrigin::root(), Some(27_000_000 * TOKEN), None),
            Ok(())
        );
    });
}

#[test]
fn only_root_can_set_inflation_parameters() {
    new_test_ext(&[(1u64, 1u64), (2u64, 2u64)]).execute_with(|| {
        assert!(Aleph::set_inflation_parameters(
            RuntimeOrigin::signed(1),
            Some(27_000_000 * TOKEN),
            None
        )
        .is_err());
        assert_eq!(AzeroCap::<Test>::get(), HARD_SUPPLY_CAP);
    });
}
