use primitives::{
    AccountId, Version as FinalityVersion, CURRENT_FINALITY_VERSION, LEGACY_FINALITY_VERSION,
};
use sc_chain_spec::ChainType;
use sc_cli::clap::{self, Args};

use crate::chain_spec::{parse_account_id, parse_chaintype, CHAINTYPE_LIVE, DEFAULT_CHAIN_ID};

/// Chỉ nhận đúng hai giá trị, kiểm tra ngay lúc clap parse.
///
/// Bản cũ để `finality_version` là String tự do rồi `panic!` trong getter — tức
/// gõ sai chính tả thì node chạy được một đoạn mới chết, giữa lúc bootstrap.
fn parse_finality_version(s: &str) -> Result<String, String> {
    match s {
        "current" | "legacy" => Ok(s.to_string()),
        other => Err(format!(
            "'{other}' không hợp lệ, chỉ nhận 'current' hoặc 'legacy'"
        )),
    }
}

#[derive(Debug, Args, Clone)]
pub struct ChainSpecParams {
    /// Chain ID is a short identifier of the chain
    #[arg(long, value_name = "ID", default_value = DEFAULT_CHAIN_ID)]
    chain_id: String,

    /// The type of the chain. Possible values: "dev", "local", "live" (default)
    #[arg(long, value_name = "TYPE", value_parser = parse_chaintype, default_value = CHAINTYPE_LIVE)]
    chain_type: ChainType,

    /// Chain name — tên hiển thị trong ví và explorer.
    /// Đổi bằng --chain-name nếu muốn tên hiển thị khác định danh kỹ thuật.
    #[arg(long, default_value = "Pinode7911")]
    chain_name: String,

    /// Token symbol.
    ///
    /// Lưu ý: dự án Pi Network (minepi.com) đã dùng ký hiệu "PI" và rất nhiều
    /// người biết. Rủi ro nhầm lẫn và nhãn hiệu, không phải vấn đề kỹ thuật —
    /// nhưng đổi ký hiệu sau khi phát hành là phải làm lại chain.
    #[arg(long, default_value = "PI")]
    token_symbol: String,

    /// all account ids that needs to have session keys generated when bootstraping chain (comma delimited)
    #[arg(long, value_delimiter = ',', value_parser = parse_account_id)]
    account_ids: Vec<AccountId>,

    /// AccountIds of authorities forming the committee at the genesis (comma delimited)
    /// If empty, then `--account-ids` are used as authorities.
    /// If not empty, it should be a subset of `--account-ids`.
    #[arg(long, value_delimiter = ',', value_parser = parse_account_id)]
    authorities_account_ids: Vec<AccountId>,

    /// AccountId của ví sudo. BẮT BUỘC truyền.
    ///
    /// Trước đây mặc định là Alice — tài khoản dev sinh từ seed công khai
    /// ("//Alice"), ai trên thế giới cũng ký thay được. Mặc định đó nghĩa là
    /// quên một tham số thì mạng thật ra đời với khoá tối cao ai cũng có, mà
    /// chainspec sinh ra trông hoàn toàn bình thường.
    ///
    /// Khuyến nghị: multisig 2/3 hoặc 3/5, khoá trên các thiết bị khác nhau.
    #[arg(long, value_parser = parse_account_id)]
    sudo_account_id: AccountId,

    /// AccountId nhận quỹ dự trữ (999.000 PI, vesting tuyến tính 4 năm).
    ///
    /// Cũng không có mặc định, cùng lý do. Không được trùng --sudo-account-id
    /// hay bất kỳ --account-ids nào; builder kiểm tra và từ chối nếu trùng.
    #[arg(long, value_parser = parse_account_id)]
    reserve_account_id: AccountId,

    /// Accounts that will receive initial endowment in genesis block
    #[arg(long, value_delimiter = ',', value_parser = parse_account_id)]
    rich_account_ids: Option<Vec<AccountId>>,

    /// Finality version at chain inception. "current" hoặc "legacy".
    #[arg(long, value_parser = parse_finality_version, default_value = "legacy")]
    finality_version: String,
}

impl ChainSpecParams {
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    pub fn chain_type(&self) -> ChainType {
        self.chain_type.clone()
    }

    pub fn chain_name(&self) -> &str {
        &self.chain_name
    }

    pub fn token_symbol(&self) -> &str {
        &self.token_symbol
    }

    pub fn account_ids(&self) -> Vec<AccountId> {
        self.account_ids.clone()
    }

    pub fn authorities_account_ids(&self) -> Vec<AccountId> {
        self.authorities_account_ids.clone()
    }

    pub fn sudo_account_id(&self) -> AccountId {
        self.sudo_account_id.clone()
    }

    pub fn reserve_account_id(&self) -> AccountId {
        self.reserve_account_id.clone()
    }

    pub fn rich_account_ids(&self) -> Option<Vec<AccountId>> {
        self.rich_account_ids.clone()
    }

    pub fn finality_version(&self) -> FinalityVersion {
        match self.finality_version.as_str() {
            "current" => CURRENT_FINALITY_VERSION,
            "legacy" => LEGACY_FINALITY_VERSION,
            // `parse_finality_version` đã chặn từ lúc parse, nhánh này không tới được.
            other => unreachable!("giá trị chưa được kiểm tra lọt qua clap: {other}"),
        }
        .into()
    }
}
