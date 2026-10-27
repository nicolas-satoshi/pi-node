//! Mock runtime tối thiểu cho `pallet-zk-rollup-verifier` — cần để
//! `impl_benchmark_test_suite!` trong `benchmarking.rs` compile được, và để
//! viết unit test cho pallet (trước đây pallet KHÔNG có test nào cả).
//!
//! Đơn giản hơn nhiều so với `pallets/aleph/src/mock.rs` (không cần
//! session, không cần balances) — pallet này chỉ cần `frame_system` làm
//! nền.

use frame_support::{construct_runtime, derive_impl, parameter_types, traits::ConstU32};
use sp_core::H256;
use sp_runtime::{traits::IdentityLookup, BuildStorage};

use super::*;
use crate as pallet_zk_rollup_verifier;

type Block = frame_system::mocking::MockBlock<Test>;
pub(crate) type AccountId = u64;

construct_runtime!(
    pub enum Test
    {
        System: frame_system,
        ZkRollupVerifier: pallet_zk_rollup_verifier,
    }
);

// `derive_impl` lấy default test config của frame_system, chỉ override
// những gì thật sự cần khác — tránh phải liệt kê thủ công 20 dòng như bản
// mock.rs cũ trong `pallets/aleph` (bản đó viết trước khi macro này có,
// giữ style cũ ở đó để không phá vỡ test hiện có, dùng macro mới ở đây vì
// pallet là mới hoàn toàn).
#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Hash = H256;
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type PalletInfo = PalletInfo;
}

parameter_types! {
    pub const TestMaxProofSize: u32 = 64 * 1024;
    pub const TestMaxVerificationKeySize: u32 = 16 * 1024;
    pub const TestChainId: u64 = 999; // giá trị test riêng, KHÔNG trùng
                                       // devnet(?) hay mainnet(1) thật, để
                                       // lỡ ai copy-paste nhầm proof test
                                       // sang môi trường khác cũng bị domain
                                       // separator chặn ngay.
    pub const TestMaxBatchDataSize: u32 = 4 * 1024;
    pub const TestDataRetentionBatches: u64 = 3; // nhỏ, để test pruning dễ
                                                   // observe trong vài batch
                                                   // thay vì phải chạy 10_080
                                                   // lần như production.
}

/// Verifier giả cho unit test VÀ cho benchmark sanity-check
/// (`impl_benchmark_test_suite!` chạy dưới `mock::Test`, không phải runtime
/// thật — mục đích là kiểm tra logic extrinsic không panic/lỗi, KHÔNG phải
/// đo weight thật; số weight thật chỉ có được khi chạy benchmark CLI trên
/// `bin/runtime` thật với verifier thật, xem benchmarking.rs).
///
/// Logic CỐ Ý đơn giản — giống hệt `DevInsecureVerifier` thật của pallet
/// (`!proof.is_empty()`), KHÔNG check chuỗi cố định như `b"VALID"`: nếu
/// check cứng một chuỗi cụ thể, benchmark test suite sẽ fail ngay vì
/// `FIXTURE_SP1_PROOF`/`FIXTURE_RISC0_PROOF` trong benchmarking.rs là bytes
/// Groth16 thật, không phải chuỗi giả `b"VALID"`. Dùng lại đúng logic
/// "khác rỗng = pass" để cả 2 nơi gọi tới (unit test viết tay, và benchmark
/// dùng fixture thật) đều hoạt động nhất quán mà không cần biết nội dung
/// proof cụ thể là gì.
pub struct MockVerifier;

#[cfg(feature = "std")]
std::thread_local! {
    /// Public values của lần `verify` gần nhất — để test kiểm tra đúng những gì
    /// pallet đưa cho verifier (chain_id, batch_index, data_hash...).
    pub static LAST_PUBLIC_VALUES: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

impl ZkVerifier for MockVerifier {
    fn verify(proof: &[u8], _vk: &[u8], public_values: &[u8]) -> bool {
        #[cfg(feature = "std")]
        LAST_PUBLIC_VALUES.with(|last| *last.borrow_mut() = public_values.to_vec());
        #[cfg(not(feature = "std"))]
        let _ = public_values;
        !proof.is_empty()
    }
}

impl Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Sp1Verifier = MockVerifier;
    type Risc0Verifier = MockVerifier;
    type MaxProofSize = TestMaxProofSize;
    type MaxVerificationKeySize = TestMaxVerificationKeySize;
    type ChainId = TestChainId;
    type AdminOrigin = frame_system::EnsureRoot<AccountId>;
    type MaxBatchDataSize = TestMaxBatchDataSize;
    type DataRetentionBatches = TestDataRetentionBatches;
    type WeightInfo = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = <frame_system::GenesisConfig<Test> as BuildStorage>::build_storage(
        &frame_system::GenesisConfig::default(),
    )
    .expect("Storage should be build.");
    t.into()
}
