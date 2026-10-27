mod builder;
mod cli;
pub mod commands;
mod keystore;

pub use commands::{BootstrapChainCmd, ConvertChainspecToRawCmd};

pub const CHAINTYPE_DEV: &str = "dev";
pub const CHAINTYPE_LOCAL: &str = "local";
pub const CHAINTYPE_LIVE: &str = "live";

/// Định danh chain, dùng làm tên thư mục dữ liệu.
/// Cũ là "a0dPIv1" — vẫn còn tiền tố a0d của Aleph Zero.
pub const DEFAULT_CHAIN_ID: &str = "Pinode7911";

pub type AlephNodeChainSpec = sc_service::GenericChainSpec<()>;

use primitives::AccountId;
use sc_chain_spec::ChainType;
use sc_cli::Error;
use sp_application_crypto::Ss58Codec;

fn parse_chaintype(s: &str) -> Result<ChainType, Error> {
    Ok(match s {
        CHAINTYPE_DEV => ChainType::Development,
        CHAINTYPE_LOCAL => ChainType::Local,
        CHAINTYPE_LIVE => ChainType::Live,
        s => panic!("Wrong chain type {s} Possible values: dev local live"),
    })
}

/// Generate AccountId based on string command line argument.
///
/// Trả `Err` thay vì `expect`: `--sudo-account-id` và `--reserve-account-id`
/// giờ bắt buộc gõ tay, nên gõ nhầm một ký tự phải ra lỗi clap tử tế chứ không
/// phải panic kèm thông báo sai nội dung (bản cũ nói về "hex encoding" trong
/// khi đầu vào là SS58).
fn parse_account_id(s: &str) -> Result<AccountId, Error> {
    AccountId::from_string(s)
        .map_err(|e| Error::Input(format!("'{s}' không phải địa chỉ SS58 hợp lệ: {e:?}")))
}
