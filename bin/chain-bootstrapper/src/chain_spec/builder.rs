use std::string::ToString;

use aleph_runtime::WASM_BINARY;
use pallet_staking::{Forcing, StakerStatus};
use primitives::{
    staking::{MIN_NOMINATOR_BOND, MIN_VALIDATOR_BOND},
    AccountId, AlephNodeSessionKeys, Version as FinalityVersion, ADDRESSES_ENCODING, TOKEN,
    TOKEN_DECIMALS,
};
use serde_json::{Number, Value};
use sp_runtime::Perbill;

use crate::chain_spec::{cli::ChainSpecParams, keystore::AccountSessionKeys, AlephNodeChainSpec};

fn to_account_ids(authorities: &[AccountSessionKeys]) -> impl Iterator<Item = AccountId> + '_ {
    authorities.iter().map(|auth| auth.account_id.clone())
}

fn system_properties(token_symbol: String) -> serde_json::map::Map<String, Value> {
    [
        ("tokenSymbol".to_string(), Value::String(token_symbol)),
        (
            "tokenDecimals".to_string(),
            Value::Number(Number::from(TOKEN_DECIMALS)),
        ),
        (
            "ss58Format".to_string(),
            Value::Number(Number::from(ADDRESSES_ENCODING)),
        ),
    ]
    .iter()
    .cloned()
    .collect()
}

/// Generate chain spec for new AlephNode chains
pub fn build_chain_spec(
    chain_params: &ChainSpecParams,
    account_session_keys: Vec<AccountSessionKeys>,
) -> Result<AlephNodeChainSpec, String> {
    let token_symbol = String::from(chain_params.token_symbol());
    let sudo_account = chain_params.sudo_account_id();
    let rich_accounts = chain_params.rich_account_ids();
    let finality_version = chain_params.finality_version();

    // Địa chỉ Treasury do chính pallet sinh ra từ `PalletId` — không ai có khoá
    // riêng cho nó, tiền chỉ ra được qua đề xuất chi tiêu. Lấy trực tiếp từ
    // runtime thay vì chép cứng một chuỗi SS58, để không bao giờ lệch.
    let treasury_account = aleph_runtime::Treasury::account_id();

    // Quỹ dự trữ (vesting 4 năm). BẮT BUỘC truyền vào, không có mặc định —
    // nếu để mặc định thì rất dễ vô tình phát hành mạng thật với ví dev.
    let reserve_account = chain_params.reserve_account_id();

    // Không cho một tài khoản giữ hai vai.
    //
    // Ngoài lý do quản trị (sudo trùng ví dự trữ thì vesting mất hết ý nghĩa vì
    // cùng một khoá vừa nắm quyền vừa nắm quỹ), còn một lý do kỹ thuật: `balances`
    // genesis không chấp nhận tài khoản lặp, trùng là node panic lúc bootstrap
    // với thông báo khó lần ra nguyên nhân.
    if reserve_account == sudo_account {
        return Err("--reserve-account-id trùng --sudo-account-id".to_string());
    }
    for keys in account_session_keys.iter() {
        if keys.account_id == sudo_account {
            return Err(format!(
                "Tài khoản validator {} trùng --sudo-account-id",
                keys.account_id
            ));
        }
        if keys.account_id == reserve_account {
            return Err(format!(
                "Tài khoản validator {} trùng --reserve-account-id",
                keys.account_id
            ));
        }
    }
    if let Some(rich) = rich_accounts.as_ref() {
        for account in rich {
            if *account == sudo_account || *account == reserve_account {
                return Err(format!("--rich-account-ids chứa {account}, đã có vai khác"));
            }
        }
    }

    Ok(AlephNodeChainSpec::builder(
        WASM_BINARY.ok_or("AlephNode development wasm not available")?,
        Default::default(),
    )
    .with_name(chain_params.chain_name())
    .with_id(chain_params.chain_id())
    .with_chain_type(chain_params.chain_type())
    .with_genesis_config_patch(generate_genesis_config(
        account_session_keys,
        sudo_account,
        treasury_account,
        reserve_account,
        rich_accounts,
        finality_version,
    ))
    .with_properties(system_properties(token_symbol))
    .build())
}

/// Tổng cung tại genesis. Trần của cơ chế lạm phát staking là 28 triệu:
/// `pallet_aleph::DefaultAzeroCap` (điều chỉnh được qua sudo, nhưng bị chặn bởi
/// `primitives::HARD_SUPPLY_CAP` trong mã runtime và giới hạn 30 ngày/lần đổi).
/// 21 triệu còn lại sẽ được đúc dần qua thưởng staking, tiệm cận mà không chạm trần.
/// Xem TOKENOMICS.md.
const GENESIS_TOTAL_ISSUANCE: u128 = 7_000_000 * TOKEN;

/// Mỗi validator genesis nhận từng này.
const VALIDATOR_ENDOWMENT: u128 = 700_000 * TOKEN;

/// ...và bond sẵn từng này (6/7 số được cấp), giữ lại phần còn lại để trả phí.
///
/// # Vì sao con số này quan trọng hơn nó trông
///
/// `ExponentialEraPayout` đúc ra một lượng CỐ ĐỊNH mỗi era, không phụ thuộc có
/// bao nhiêu tiền đang stake. Chia cho ít người thì mỗi người nhiều.
///
/// Bản cũ bond `(idx + 1) * MIN_VALIDATOR_BOND` = 100, 200 … 600 PI, tổng
/// 2.100 PI trên tổng cung 7 triệu — tức 0,03%. Với horizon 10 năm, năm đầu
/// đúc ~2 triệu PI chia cho 2.100 PI đang stake: **APR khoảng 90.000%**. Sáu ví
/// genesis sẽ nuốt gần hết 21 triệu trước khi có người ngoài kịp tham gia.
///
/// 600.000 × 6 = 3,6 triệu PI được stake (51% tổng cung, ngang Polkadot) cho
/// **APR năm đầu 49,96%** — con số bình thường của một chain PoS.
const VALIDATOR_BOND: u128 = 600_000 * TOKEN;

/// Treasury nhận 1,8 triệu. Cộng thêm 10% mọi khoản thưởng staking chảy vào
/// qua `RewardRemainder`, và phí giao dịch.
const TREASURY_ENDOWMENT: u128 = 1_800_000 * TOKEN;

/// Quỹ dự trữ, mở khoá tuyến tính trong 4 năm (xem `vesting` bên dưới).
const RESERVE_ENDOWMENT: u128 = 999_000 * TOKEN;

/// Sudo chỉ nhận đủ để trả phí giao dịch.
///
/// Tách quyền quản trị khỏi tài sản: một ví vừa có quyền tối cao vừa nắm 14%
/// tổng cung là thứ người ngoài soi đầu tiên, và cũng là một mục tiêu tấn công
/// đáng giá gấp đôi.
const SUDO_ENDOWMENT: u128 = 1_000 * TOKEN;

/// Block mỗi năm: 365,25 ngày ÷ 3 giây/block.
const BLOCKS_PER_YEAR: u128 = 10_519_200;

/// Số ghế uỷ ban dành cho validator KHÔNG thuộc nhóm genesis.
///
/// Để 0 tại genesis vì danh sách non-reserved đang rỗng: đặt 3 ghế cho 0 ứng
/// viên là trạng thái tự mâu thuẫn, và `ensure_validators_are_ok` sẽ từ chối
/// mọi lần gọi `change_validators` sau này cho tới khi có đủ 3 người thật.
///
/// Mở mạng cho validator ngoài là việc làm SAU khi chain chạy, bằng sudo:
///   1. `elections::change_validators` — thêm non-reserved và cấp ghế cho họ
///   2. `elections::set_elections_openness(Permissionless)` — bỏ cổng duyệt
///
/// Phải làm cả hai. `Openness` mặc định là `Permissioned`, nghĩa là dù có ghế
/// trống thì ứng viên mới bond token vẫn không tự vào được; danh sách
/// non-reserved chỉ thay đổi khi sudo chỉ định.
const NON_RESERVED_SEATS: u32 = 0;

/// Ghế finality dành cho non-reserved. Bắt buộc `<=` NON_RESERVED_SEATS.
///
/// `CommitteeSeats::default()` của upstream đặt trường này là 6 trong khi
/// `non_reserved_seats` là 0 — vi phạm chính bất biến mà `change_validators`
/// cưỡng chế. Genesis không kiểm tra nên chain vẫn khởi động, chỉ là khởi động
/// vào một trạng thái mà extrinsic của chính runtime đó sẽ từ chối. Đặt tường
/// minh để không thừa hưởng cái mặc định đó.
const NON_RESERVED_FINALITY_SEATS: u32 = 0;

/// Configure initial storage state for FRAME modules.
fn generate_genesis_config(
    account_session_keys: Vec<AccountSessionKeys>,
    sudo_account: AccountId,
    treasury_account: AccountId,
    reserve_account: AccountId,
    rich_accounts: Option<Vec<AccountId>>,
    finality_version: FinalityVersion,
) -> serde_json::Value {
    let validators = to_account_ids(&account_session_keys).collect::<Vec<_>>();

    let mut balances: Vec<(AccountId, u128)> = validators
        .iter()
        .cloned()
        .map(|account| (account, VALIDATOR_ENDOWMENT))
        .collect();

    balances.push((treasury_account, TREASURY_ENDOWMENT));
    balances.push((reserve_account.clone(), RESERVE_ENDOWMENT));
    balances.push((sudo_account.clone(), SUDO_ENDOWMENT));

    // `rich_accounts` chia nhau phần dư, nếu có. Giữ tuỳ chọn này để chạy thử
    // cục bộ vẫn tiện, nhưng mạng thật nên để trống.
    let allocated: u128 = balances.iter().map(|(_, amount)| *amount).sum();
    let remainder = GENESIS_TOTAL_ISSUANCE.saturating_sub(allocated);
    let rich = rich_accounts.unwrap_or_default();
    if !rich.is_empty() && remainder > 0 {
        let each = remainder / rich.len() as u128;
        for account in rich {
            balances.push((account, each));
        }
    }

    // Kiểm tra ngay tại đây thay vì phát hiện sau khi chain đã chạy: phân bổ
    // genesis là thứ KHÔNG sửa được, nên sai một đồng cũng phải dừng lại.
    //
    // Dùng `==` chứ không phải `<=`: thiếu tiền cũng là lỗi, và là lỗi im lặng —
    // chainspec vẫn sinh ra bình thường, chỉ khác là tổng cung không như công bố.
    let total: u128 = balances.iter().map(|(_, amount)| *amount).sum();
    assert_eq!(
        total, GENESIS_TOTAL_ISSUANCE,
        "Phân bổ genesis ({total}) khác tổng cung dự kiến ({GENESIS_TOTAL_ISSUANCE})"
    );

    // Vesting cho quỹ dự trữ: mở khoá tuyến tính trong 4 năm, bắt đầu ngay từ
    // block 0. Ai cũng kiểm tra được on-chain là số PI này không thể bán tháo —
    // ràng buộc do chain cưỡng chế, mạnh hơn nhiều so với một lời hứa.
    let vesting_blocks = BLOCKS_PER_YEAR * 4;

    // Trường thứ tư của genesis vesting là `liquid` — phần KHÔNG bị khoá tại
    // genesis. Pallet tự tính `locked = free_balance - liquid` rồi chia cho
    // `length` ra tốc độ mở khoá mỗi block; ta không tự tính per-block.
    //
    // Để 0 = khoá toàn bộ 999.000 PI. Ví vẫn trả được phí giao dịch, vì lock
    // của pallet_vesting đặt với `WithdrawReasons::except(TRANSACTION_PAYMENT)`.
    let liquid_at_genesis: u128 = 0;

    serde_json::json!({
        "balances": {
            "balances": balances,
        },
        "vesting": {
            // (tài khoản, block bắt đầu, số block mở khoá, phần thanh khoản ngay)
            "vesting": [
                (reserve_account, 0u32, vesting_blocks as u32, liquid_at_genesis),
            ],
        },
        "sudo": {
            "key": Some(sudo_account),
        },
        "elections": {
            "reservedValidators": validators.clone(),
            // Đặt tường minh cả ba trường thay vì để rơi về `Default`.
            //
            // `CommitteeSeats::default()` là {reserved: 6, non_reserved: 0,
            // non_reserved_finality: 6} — số 6 cuối lớn hơn số 0 ở giữa, vi phạm
            // chính bất biến `non_reserved_finality <= non_reserved` mà
            // `change_validators` cưỡng chế. `genesis_build` không kiểm tra gì
            // (`ensure_validators_are_ok` chỉ chạy trong extrinsic), nên chain
            // khởi động bình thường rồi mang trạng thái đó đi mãi.
            "nonReservedValidators": Vec::<AccountId>::new(),
            "committeeSeats": {
                "reservedSeats": validators.len() as u32,
                "nonReservedSeats": NON_RESERVED_SEATS,
                "nonReservedFinalitySeats": NON_RESERVED_FINALITY_SEATS,
            },
        },
        "session": {
           "keys": account_session_keys
                    .iter()
                    .map(|auth| {
                        (
                            auth.account_id.clone(),
                            auth.account_id.clone(),
                            AlephNodeSessionKeys {
                                aura: auth.aura_key.clone(),
                                aleph: auth.aleph_key.clone(),
                            },
                        )
                    })
                    .collect::<Vec<_>>(),
        },
        "staking": {
            "forceEra": Forcing::NotForcing,
            "validatorCount":  account_session_keys.len() as u32,
            // Ngưỡng finalize của AlephBFT là 2N/3+1. Để 1 nghĩa là staking vẫn
            // cho era chạy tiếp với đúng một validator — chain trượt về tập
            // trung hoàn toàn thay vì dừng lại. Đặt bằng ngưỡng thật.
            "minimumValidatorCount": 2 * (account_session_keys.len() as u32) / 3 + 1,
            "slashRewardFraction": Perbill::from_percent(10),
            "stakers": account_session_keys
                        .iter()
                        .map(|validator| {
                            (
                                validator.account_id.clone(),
                                validator.account_id.clone(),
                                VALIDATOR_BOND,
                                StakerStatus::<AccountId>::Validator,
                            )
                        })
                        .collect::<Vec<_>>(),
            "minValidatorBond": MIN_VALIDATOR_BOND,
            "minNominatorBond": MIN_NOMINATOR_BOND,
        },
        "aleph": {
            "finalityVersion": finality_version,
        },
        "committeeManagement": {
            "sessionValidators": {
                "committee": validators,
            },
        },
    })
}

pub fn build_chain_spec_json(
    is_raw_chainspec: bool,
    chain_params: &ChainSpecParams,
    account_session_keys: Vec<AccountSessionKeys>,
) -> sc_service::error::Result<String> {
    let chain_spec = build_chain_spec(chain_params, account_session_keys)?;
    sc_service::chain_ops::build_spec(&chain_spec, is_raw_chainspec)
}
