//! # Pallet ZK Rollup Verifier
//!
//! Nhận batch từ L2 sequencer, xác thực bằng HAI hệ prover độc lập (SP1 + Risc0),
//! và chỉ cập nhật state root của L2 trên L1 khi cả hai đều hợp lệ.
//!
//! ## Khác biệt so với bản nháp cũ
//! - Không phụ thuộc trực tiếp vào `sp1_sdk` / `risc0_zkvm` (hai crate đó là `std`,
//!   không nhúng được vào runtime WASM). Thay vào đó pallet định nghĩa trait
//!   [`ZkVerifier`] để runtime cắm implementation `no_std` vào.
//! - Public values được so khớp bằng SCALE codec ở CẢ hai phía (pallet và guest).
//! - Proof/verification key dùng `BoundedVec` để tránh DoS bằng payload khổng lồ.
//! - Có extrinsic để set verification key và sequencer (bản cũ khai báo storage
//!   nhưng không có cách nào ghi vào).

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
// `mock` cần cho CẢ HAI: unit test (`cfg(test)`) VÀ benchmark CLI build
// (`cfg(feature = "runtime-benchmarks")`, không nhất thiết có `cfg(test)`
// — benchmark thường chạy qua `cargo build --features runtime-benchmarks`
// rồi gọi binary, không phải qua `cargo test`). Gate riêng `cfg(test)` sẽ
// khiến `benchmarking.rs` không tìm thấy `crate::mock::Test` khi build cho
// benchmark CLI mà không đồng thời chạy test.
#[cfg(any(test, feature = "runtime-benchmarks"))]
mod mock;
#[cfg(test)]
mod tests;

use frame_support::pallet_prelude::*;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;

/// Root của cây Merkle account RỖNG (độ sâu 256, lá rỗng = 32 byte 0). Dùng làm
/// state root khởi tạo của L2.
///
/// PHẢI khớp `l2_guest::smt::EMPTY_STATE_ROOT`. Test `empty_state_root_matches_formula`
/// tính lại giá trị này bằng SHA-256; guest có test tương ứng.
///
/// Bản trước để mặc định `[0; 32]` — không phải root của bất kỳ cây hợp lệ nào, nên
/// không có proof nào chứng minh được batch đầu tiên và L2 kẹt ngay từ đầu.
pub const EMPTY_STATE_ROOT: [u8; 32] = [
    0xb1, 0x78, 0xc2, 0x45, 0xc9, 0x47, 0xea, 0x7e, 0x21, 0xec, 0xed, 0xe0, 0x77, 0x28, 0x94, 0x1a,
    0x6a, 0xb1, 0xb7, 0x06, 0x14, 0x3c, 0x06, 0x87, 0x3b, 0xaf, 0xf8, 0xeb, 0xd6, 0xde, 0x63, 0x08,
];

/// Public values mà chương trình guest commit ra, và L1 dùng để đối chiếu.
///
/// QUAN TRỌNG: struct này phải khớp BYTE-FOR-BYTE với `RollupOutput` trong
/// `l2-guest`. Cả hai đều encode bằng SCALE, cùng thứ tự field.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, RuntimeDebug)]
pub struct RollupStateCommitment {
    /// Domain separator theo phiên bản. Đổi khi layout commitment đổi, để proof
    /// của layout cũ không còn hợp lệ.
    pub version: u8,
    /// Chain ID — chặn replay proof từ devnet sang mainnet (và ngược lại).
    pub chain_id: u64,
    /// Thứ tự batch. Chặn replay theo chu trình A->B->A: proof gắn với đúng
    /// một vị trí trong chuỗi batch, không dùng lại được.
    pub batch_index: u64,
    pub old_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    /// SHA-256 của blob `transaction_data` được đăng on-chain. Pallet tự băm blob
    /// nhận được rồi đưa vào đây, nên proof chỉ hợp lệ nếu blob đúng là danh sách
    /// giao dịch mà guest đã chứng minh (data availability có ràng buộc).
    pub data_hash: [u8; 32],
}

/// Phiên bản layout commitment hiện tại.
///
/// 3: thêm `data_hash`; cây Merkle 256 bit với `account_id` trong lá; chữ ký giao
/// dịch L2 có `chain_id`. Phải khớp `l2_guest::COMMITMENT_VERSION`. Proof theo
/// layout cũ tự động hết hiệu lực nhờ domain separator này.
pub const COMMITMENT_VERSION: u8 = 3;

/// Trait trừu tượng hoá một hệ thống xác thực ZK proof.
///
/// Runtime chịu trách nhiệm cung cấp implementation `no_std`. Xem `HUONG_DAN.md`
/// mục "Cắm verifier thật".
pub trait ZkVerifier {
    /// `proof`: bằng chứng đã serialize.
    /// `vk`: verification key (SP1) hoặc method id (Risc0).
    /// `public_values`: SCALE-encoded [`RollupStateCommitment`].
    fn verify(proof: &[u8], vk: &[u8], public_values: &[u8]) -> bool;
}

/// Verifier mặc định AN TOÀN: từ chối mọi proof.
///
/// Dùng cái này khi chưa cắm verifier thật, để không ai submit được state root giả.
pub struct RejectAllVerifier;

impl ZkVerifier for RejectAllVerifier {
    fn verify(_proof: &[u8], _vk: &[u8], _public_values: &[u8]) -> bool {
        false
    }
}

/// ⚠️ CHỈ DÙNG TRÊN DEVNET. Chấp nhận mọi proof khác rỗng.
///
/// Bật bằng feature `dev-insecure-verifier`. TUYỆT ĐỐI không bật trên mainnet:
/// bất kỳ ai cũng ghi đè được state root của L2.
#[cfg(all(
    feature = "dev-insecure-verifier",
    not(feature = "i-understand-this-is-insecure")
))]
compile_error!(
    "Feature `dev-insecure-verifier` chấp nhận MỌI proof — bất kỳ ai cũng ghi đè \
     được state root của L2. Cargo feature là additive nên nó có thể bị bật gián \
     tiếp bởi một crate khác mà bạn không để ý. Nếu thật sự muốn build devnet, \
     bật kèm feature `i-understand-this-is-insecure`."
);

#[cfg(feature = "dev-insecure-verifier")]
pub struct DevInsecureVerifier;

#[cfg(feature = "dev-insecure-verifier")]
impl ZkVerifier for DevInsecureVerifier {
    fn verify(proof: &[u8], _vk: &[u8], _public_values: &[u8]) -> bool {
        !proof.is_empty()
    }
}

/// Weight cho các extrinsic. Giá trị dưới đây là ƯỚC LƯỢNG THÔ — phải benchmark
/// trước khi lên mainnet.
///
/// RÀNG BUỘC CỨNG: weight khai báo của một extrinsic phải NHỎ HƠN giới hạn block
/// (`MAX_BLOCK_WEIGHT` = 400ms, lớp Normal tối đa 99%). Bản trước khai báo 500ms nên
/// `submit_l2_batch` không bao giờ lọt vào block, ngay cả khi dùng verifier dev.
/// Test `l2_batch_weight_fits_in_a_block` trong `bin/runtime` canh điều này.
///
/// Con số hợp lý vì verify chạy NATIVE qua host function (xem `primitives::zk_host`):
/// một Groth16 verify native cỡ vài ms. Nếu sau này đưa verify vào WASM thì weight
/// sẽ vượt block và thiết kế phải đổi.
pub trait WeightInfo {
    fn submit_l2_batch() -> Weight;
    /// Weight khi batch bị loại ở các kiểm tra rẻ tiền, TRƯỚC khi verify proof.
    fn submit_l2_batch_rejected() -> Weight;
    /// Weight khi đã chạy verify SP1 nhưng fail (Risc0 chưa chạy).
    fn submit_l2_batch_sp1_failed() -> Weight;
    /// Phần weight tăng theo độ dài `transaction_data` (băm + ghi storage + proof size).
    fn data_write(len: u32) -> Weight;
    fn set_sp1_verification_key() -> Weight;
    fn set_risc0_method_id() -> Weight;
    fn set_sequencer() -> Weight;
}

impl WeightInfo for () {
    fn submit_l2_batch() -> Weight {
        // Hai lần verify native (SP1 + Risc0) + vài lần đọc/ghi storage, chưa gồm
        // phần tăng theo độ dài dữ liệu (xem `data_write`).
        Weight::from_parts(60_000_000_000, 4_096)
    }
    fn submit_l2_batch_rejected() -> Weight {
        // Chỉ vài lần đọc storage, không verify gì.
        Weight::from_parts(30_000_000, 1_024)
    }
    fn submit_l2_batch_sp1_failed() -> Weight {
        // Khoảng một nửa: đã verify SP1, chưa verify Risc0.
        Weight::from_parts(30_000_000_000, 2_048)
    }
    fn data_write(len: u32) -> Weight {
        // ~25ns/byte cho băm + ghi; proof size tăng đúng bằng số byte được ghi.
        Weight::from_parts(25_000u64.saturating_mul(len as u64), len as u64)
    }
    fn set_sp1_verification_key() -> Weight {
        Weight::from_parts(20_000_000, 0)
    }
    fn set_risc0_method_id() -> Weight {
        Weight::from_parts(20_000_000, 0)
    }
    fn set_sequencer() -> Weight {
        Weight::from_parts(20_000_000, 0)
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::dispatch::{
        DispatchErrorWithPostInfo, DispatchResultWithPostInfo, Pays, PostDispatchInfo,
    };
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Verifier cho hệ SP1.
        type Sp1Verifier: ZkVerifier;

        /// Verifier cho hệ Risc0.
        type Risc0Verifier: ZkVerifier;

        /// Kích thước tối đa của một proof (bytes).
        #[pallet::constant]
        type MaxProofSize: Get<u32>;

        /// Kích thước tối đa của verification key (bytes).
        #[pallet::constant]
        type MaxVerificationKeySize: Get<u32>;

        /// Chain ID dùng làm domain separator trong commitment.
        /// PHẢI khác nhau giữa devnet và mainnet.
        #[pallet::constant]
        type ChainId: Get<u64>;

        /// Origin được phép đổi verification key / sequencer. Thường là Root.
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        /// Kích thước tối đa dữ liệu transaction thô của MỘT batch, lưu
        /// on-chain để làm data availability (xem storage `BatchTransactionData`
        /// bên dưới). Đây là phần trước đây HOÀN TOÀN THIẾU — pallet chỉ
        /// lưu state root, không lưu gì để ai đó reconstruct lại state nếu
        /// sequencer biến mất (đúng lỗ hổng đã ghi trong L2_HUONG_DAN.md
        /// mục 5 "Data availability").
        #[pallet::constant]
        type MaxBatchDataSize: Get<u32>;

        /// Số batch gần nhất giữ transaction data on-chain trước khi bị dọn
        /// (pruned). ĐÂY LÀ ĐÁNH ĐỔI CỐ Ý, không phải giới hạn kỹ thuật:
        /// lưu vĩnh viễn on-chain là không khả thi (storage tăng vô hạn,
        /// mọi validator phải giữ mãi mãi) — cửa sổ trượt (rolling window)
        /// đủ để: (a) ai đó phát hiện + tranh chấp 1 batch gian lận trong
        /// thời gian ngắn sau khi nó xảy ra, (b) full node mới sync kịp lấy
        /// data trước khi bị dọn. Lưu trữ VĨNH VIỄN (nếu cần cho audit dài
        /// hạn) phải làm ở tầng khác — indexer/explorer off-chain đọc event
        /// `L2StateUpdated` + field data trong extrinsic (dữ liệu SIGNED
        /// EXTRINSIC vẫn nằm trong block đã finalize mãi mãi ở tầng
        /// blockchain layer, dù storage runtime đã dọn) — đây chính là lý
        /// do dữ liệu này được truyền qua EXTRINSIC PARAM chứ không chỉ qua
        /// off-chain channel: một khi block finalize, dữ liệu nằm trong
        /// block đó vĩnh viễn dù pallet storage tự dọn.
        #[pallet::constant]
        type DataRetentionBatches: Get<u64>;

        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Mặc định = root của cây account rỗng (xem `EMPTY_STATE_ROOT`). Dùng
    /// `type_value` nên chain đang chạy chưa ghi giá trị này vẫn nhận mặc định mới,
    /// không cần migration.
    #[pallet::type_value]
    pub fn DefaultStateRoot() -> [u8; 32] {
        EMPTY_STATE_ROOT
    }

    /// State root hiện tại của L2, lưu trên L1.
    #[pallet::storage]
    #[pallet::getter(fn current_l2_state)]
    pub type CurrentL2StateRoot<T: Config> =
        StorageValue<_, [u8; 32], ValueQuery, DefaultStateRoot>;

    /// Dữ liệu transaction thô của batch, đánh index theo `batch_index`.
    /// Đây là phần Data Availability — trước đây KHÔNG tồn tại (pallet chỉ
    /// lưu state root). Chỉ giữ `DataRetentionBatches` batch gần nhất, xem
    /// docstring của `Config::DataRetentionBatches` để biết vì sao và đánh
    /// đổi ra sao.
    #[pallet::storage]
    #[pallet::getter(fn batch_transaction_data)]
    pub type BatchTransactionData<T: Config> =
        StorageMap<_, Twox64Concat, u64, BoundedVec<u8, T::MaxBatchDataSize>, OptionQuery>;

    /// Verification key của chương trình L2 phía SP1.
    #[pallet::storage]
    #[pallet::getter(fn sp1_verification_key)]
    pub type Sp1VerificationKey<T: Config> =
        StorageValue<_, BoundedVec<u8, T::MaxVerificationKeySize>, ValueQuery>;

    /// Method ID của chương trình L2 phía Risc0.
    #[pallet::storage]
    #[pallet::getter(fn risc0_method_id)]
    pub type Risc0MethodId<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;

    /// Sequencer duy nhất được phép submit batch.
    ///
    /// FAIL-CLOSED: nếu là `None` thì KHÔNG ai submit được. Phải gọi
    /// `set_sequencer` bằng Root trước khi pallet nhận batch.
    #[pallet::storage]
    #[pallet::getter(fn authorized_sequencer)]
    pub type AuthorizedSequencer<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    /// Số batch đã finalize — tiện cho indexer/explorer theo dõi.
    #[pallet::storage]
    #[pallet::getter(fn batch_count)]
    pub type BatchCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Cập nhật state L2 thành công. [old_root, new_root, batch_index]
        L2StateUpdated([u8; 32], [u8; 32], u64),
        /// Dữ liệu transaction thô của 1 batch cũ đã bị dọn khỏi storage
        /// (vượt cửa sổ `DataRetentionBatches`). [batch_index đã dọn]
        BatchDataPruned(u64),
        /// Verification key của SP1 đã được thay đổi.
        Sp1VerificationKeyUpdated,
        /// Method ID của Risc0 đã được thay đổi.
        Risc0MethodIdUpdated([u8; 32]),
        /// Sequencer được phép submit đã thay đổi.
        SequencerUpdated(Option<T::AccountId>),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// `old_state_root` gửi lên không khớp state root đang lưu trên L1.
        InvalidOldStateRoot,
        /// Proof của SP1 không hợp lệ.
        Sp1ProofVerificationFailed,
        /// Proof của Risc0 không hợp lệ.
        Risc0ProofVerificationFailed,
        /// Người gửi không phải sequencer được uỷ quyền.
        NotAuthorizedSequencer,
        /// Chưa chỉ định sequencer nào — pallet đóng, không nhận batch.
        SequencerNotSet,
        /// Chưa cấu hình verification key — pallet chưa sẵn sàng nhận batch.
        VerificationKeysNotSet,
        /// Batch không làm thay đổi state (old == new) — từ chối để tránh spam.
        EmptyStateTransition,
        /// `transaction_data` gửi lên vượt `MaxBatchDataSize` — lỗi này thực
        /// ra không nên xảy ra được ở tầng runtime vì `BoundedVec` đã ép ở
        /// tầng encode/decode extrinsic (SCALE decode sẽ tự fail trước khi
        /// tới đây) — giữ lại như một lớp phòng thủ tường minh, không dựa
        /// hoàn toàn vào hành vi ngầm của decoder.
        BatchDataTooLarge,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Nộp batch L2 kèm proof từ cả hai hệ prover.
        ///
        /// Trả về `DispatchResultWithPostInfo` để hoàn lại weight khi batch bị
        /// loại sớm — nếu không, kẻ tấn công gửi rác cũng chiếm trọn weight của
        /// một lần verify ZK đầy đủ.
        #[pallet::call_index(0)]
        #[pallet::weight(
            T::WeightInfo::submit_l2_batch()
                .saturating_add(T::WeightInfo::data_write(transaction_data.len() as u32))
        )]
        pub fn submit_l2_batch(
            origin: OriginFor<T>,
            old_state_root: [u8; 32],
            new_state_root: [u8; 32],
            sp1_proof: BoundedVec<u8, T::MaxProofSize>,
            risc0_proof: BoundedVec<u8, T::MaxProofSize>,
            // Blob dữ liệu giao dịch của batch: `SCALE(Vec<SignedTransaction>)` (không
            // gồm witness). Lưu on-chain làm data availability và được RÀNG BUỘC với
            // proof: pallet băm blob bằng SHA-256 và đưa vào public values
            // (`data_hash`), nên guest phải đã chứng minh đúng danh sách giao dịch này.
            //
            // LƯU Ý CÚ PHÁP: phải là `//` thường, KHÔNG phải `///` — doc comment
            // không hợp lệ trên tham số hàm.
            transaction_data: BoundedVec<u8, T::MaxBatchDataSize>,
        ) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;

            // Trả về lỗi kèm weight thực sự đã tiêu.
            let bail = |err: Error<T>, used: Weight| -> DispatchErrorWithPostInfo {
                DispatchErrorWithPostInfo {
                    post_info: PostDispatchInfo {
                        actual_weight: Some(used),
                        pays_fee: Pays::Yes,
                    },
                    error: err.into(),
                }
            };
            let cheap = T::WeightInfo::submit_l2_batch_rejected();

            // 0. FAIL-CLOSED: chưa set sequencer thì không ai submit được.
            //    (Bản trước mặc định mở cho mọi account — sai.)
            let sequencer = AuthorizedSequencer::<T>::get()
                .ok_or_else(|| bail(Error::<T>::SequencerNotSet, cheap))?;
            if sender != sequencer {
                return Err(bail(Error::<T>::NotAuthorizedSequencer, cheap));
            }

            // 1. Từ chối transition rỗng.
            if old_state_root == new_state_root {
                return Err(bail(Error::<T>::EmptyStateTransition, cheap));
            }

            // 2. Tính liên tục của state.
            if old_state_root != CurrentL2StateRoot::<T>::get() {
                return Err(bail(Error::<T>::InvalidOldStateRoot, cheap));
            }

            // 3. Key đã cấu hình chưa.
            let sp1_vkey = Sp1VerificationKey::<T>::get();
            let risc0_method_id = Risc0MethodId::<T>::get();
            if sp1_vkey.is_empty() || risc0_method_id == [0u8; 32] {
                return Err(bail(Error::<T>::VerificationKeysNotSet, cheap));
            }

            // 4. Public values — có version, chain_id và batch_index nên proof
            //    không replay được sang chain khác hay sang vị trí khác.
            let batch_index = BatchCount::<T>::get();
            let commitment = RollupStateCommitment {
                version: COMMITMENT_VERSION,
                chain_id: T::ChainId::get(),
                batch_index,
                old_state_root,
                new_state_root,
                data_hash: sp_io::hashing::sha2_256(transaction_data.as_slice()),
            };
            let public_values = commitment.encode();

            // 5. Xác thực SP1.
            if !T::Sp1Verifier::verify(&sp1_proof, &sp1_vkey, &public_values) {
                return Err(bail(
                    Error::<T>::Sp1ProofVerificationFailed,
                    T::WeightInfo::submit_l2_batch_sp1_failed(),
                ));
            }

            // 6. Xác thực Risc0 trên CÙNG public values.
            if !T::Risc0Verifier::verify(&risc0_proof, &risc0_method_id, &public_values) {
                return Err(bail(
                    Error::<T>::Risc0ProofVerificationFailed,
                    T::WeightInfo::submit_l2_batch(),
                ));
            }

            // 7. Cập nhật state.
            CurrentL2StateRoot::<T>::put(new_state_root);
            BatchCount::<T>::put(batch_index.saturating_add(1));

            // 8. Lưu transaction data on-chain (Data Availability) — TRƯỚC
            //    ĐÂY HOÀN TOÀN THIẾU, đúng lỗ hổng đã ghi trong
            //    L2_HUONG_DAN.md mục 5: "Nếu sequencer biến mất, không ai
            //    reconstruct được state L2". Giờ mỗi batch mang theo dữ
            //    liệu transaction thô, lưu tại đúng `batch_index` của nó.
            BatchTransactionData::<T>::insert(batch_index, transaction_data);

            // 9. Dọn dữ liệu batch cũ vượt cửa sổ retention — xem docstring
            //    `Config::DataRetentionBatches`. `saturating_sub` để không
            //    panic ở vài batch đầu tiên khi batch_index còn nhỏ hơn cửa
            //    sổ (chưa có gì để dọn).
            let retention = T::DataRetentionBatches::get();
            if batch_index >= retention {
                let prune_index = batch_index - retention;
                if BatchTransactionData::<T>::take(prune_index).is_some() {
                    Self::deposit_event(Event::BatchDataPruned(prune_index));
                }
            }

            Self::deposit_event(Event::L2StateUpdated(
                old_state_root,
                new_state_root,
                batch_index,
            ));

            Ok(Pays::Yes.into())
        }

        /// Đặt verification key cho SP1. Chỉ `AdminOrigin`.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::set_sp1_verification_key())]
        pub fn set_sp1_verification_key(
            origin: OriginFor<T>,
            key: BoundedVec<u8, T::MaxVerificationKeySize>,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            Sp1VerificationKey::<T>::put(key);
            Self::deposit_event(Event::Sp1VerificationKeyUpdated);
            Ok(())
        }

        /// Đặt method ID cho Risc0. Chỉ `AdminOrigin`.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::set_risc0_method_id())]
        pub fn set_risc0_method_id(origin: OriginFor<T>, method_id: [u8; 32]) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            Risc0MethodId::<T>::put(method_id);
            Self::deposit_event(Event::Risc0MethodIdUpdated(method_id));
            Ok(())
        }

        /// Đặt (hoặc gỡ) sequencer được uỷ quyền. Chỉ `AdminOrigin`.
        ///
        /// Truyền `None` để ĐÓNG pallet — sau đó không batch nào được nhận nữa.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::set_sequencer())]
        pub fn set_sequencer(
            origin: OriginFor<T>,
            sequencer: Option<T::AccountId>,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            match &sequencer {
                Some(who) => AuthorizedSequencer::<T>::put(who.clone()),
                None => AuthorizedSequencer::<T>::kill(),
            }
            Self::deposit_event(Event::SequencerUpdated(sequencer));
            Ok(())
        }
    }
}
