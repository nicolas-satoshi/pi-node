# Tokenomics PI — nguồn cung, lạm phát và quyền hạn quản trị

Tài liệu này mô tả đúng những gì mã nguồn hiện thực hóa. Nếu mã đổi, phải cập nhật tài liệu này.

## 1. Phân bổ genesis (tổng 7.000.000 PI)

| Nhóm | Số lượng (PI) | Tỷ lệ | Ghi chú |
|---|---:|---:|---|
| 6 validator genesis (6 × 700.000) | 4.200.000 | 60,0% | Mỗi ví bond sẵn 600.000 PI |
| Treasury | 1.800.000 | 25,7% | Chỉ sudo dịch chuyển được (xem mục 4) |
| Ví reserve | 999.000 | 14,3% | Vesting tuyến tính 4 năm, bắt đầu từ block 0 |
| Ví sudo | 1.000 | 0,0% | Chỉ đủ trả phí |

`bin/chain-bootstrapper` kiểm tra tổng bằng `assert_eq!` khi tạo chainspec.

## 2. Lịch phát hành

Mỗi era (1 ngày = 32 session × 900 block × 3 giây), runtime đúc:

    mint = (1 − e^(−era/horizon)) × (cap − tổng_cung_hiện_tại)

- `cap` mặc định 28.000.000 PI, `horizon` mặc định 10 năm.
- 90% phần đúc vào validator (và nominator), 10% vào treasury.
- Lượng đúc **không phụ thuộc** vào số PI đang stake, nên APR của staker phụ thuộc tổng stake.
- Không có đốt coin: phí giao dịch và slash đều chảy vào treasury (`Burn = 0%`).
- Tổng cung tiệm cận 28 triệu PI mà không bao giờ chạm.

| Năm | Đúc (triệu PI) | Lạm phát/năm | Tổng cung cuối năm (triệu PI) | APR staker (stake 3,6 triệu PI) |
|---:|---:|---:|---:|---:|
| 1 | 2,00 | 28,5% | 9,00 | 50,0% |
| 2 | 1,81 | 20,1% | 10,81 | 45,2% |
| 3 | 1,64 | 15,1% | 12,44 | 40,9% |
| 5 | 1,34 | 9,6% | 15,26 | 33,5% |
| 10 | 0,81 | 4,2% | 20,27 | 20,3% |
| 20 | 0,30 | 1,2% | 25,16 | 7,5% |
| 30 | 0,11 | 0,4% | 26,95 | 2,7% |

Các con số trên được kiểm tra bằng test `pi_first_year_mint_matches_published_schedule`
và `pi_thirty_year_supply_stays_below_cap` trong `bin/runtime/src/lib.rs`.

## 3. Các lớp bảo vệ trần cung

1. **Công thức mint tự kẹp**: tổng cung sau khi đúc không vượt `AzeroCap`; bằng hoặc vượt cap thì mint bằng 0.
2. **Trần tuyệt đối `HARD_SUPPLY_CAP` = 28.000.000 PI** (`primitives/src/lib.rs`, hằng số trong mã runtime).
   `set_inflation_parameters` từ chối mọi `azero_cap` lớn hơn nó.
3. **Giới hạn tần suất**: hai lần `set_inflation_parameters` thành công phải cách nhau tối thiểu
   `MIN_INFLATION_PARAMS_CHANGE_INTERVAL` = 864.000 block (30 ngày).
4. **Biên theo từng lần gọi** (có sẵn từ upstream): khoảng cách tới trần chỉ đổi trong [½×, 2×]; `horizon` trong [½×, 2×].

Trước bản này (spec_version 2), lớp 2 và 3 không tồn tại: gọi liên tiếp 5 lần đã nâng trần từ 28 triệu lên khoảng 679 triệu PI.

## 4. Giới hạn còn lại — phải công bố rõ

Các điểm sau **chưa** được giải quyết bằng mã, và không nên quảng bá là "trustless" hay "trần cứng không đổi được":

- **Sudo có quyền root.** `pallet_sudo` thực thi call bằng `dispatch_bypass_filter`, nên
  `BaseCallFilter` (SafeMode/TxPause) **không** ràng buộc được sudo. Sudo có thể:
  - nâng cấp runtime bằng `System.setCode` — kể cả gỡ `HARD_SUPPLY_CAP` (nhưng việc này công khai, thấy được trên chain);
  - đặt số dư / chuyển tiền cưỡng bức (`Balances` extrinsic dành cho Root);
  - ghi storage tùy ý (`System.setStorage`), chuyển tiền treasury.
- **Treasury do sudo kiểm soát**: `ApproveOrigin`/`RejectOrigin` là khóa sudo, đề xuất chi tiêu công khai bị tắt (bond cực cao).
- **Tập trung**: khoảng 86% cung genesis (validator + treasury) nằm ở tài khoản do cùng một bên vận hành.
- **Không có cầu nối L2**: pallet `zk-rollup-verifier` không động tới `Balances`. Khi thêm deposit/withdraw phải có bất biến
  "tổng số dư L2 ≤ PI đang khóa trên L1".

### Khuyến nghị quản trị (ngoài phạm vi mã)

1. Chuyển khóa sudo sang multisig (ví dụ 3/5, các bên độc lập) trước khi có giá trị thật.
2. Đặt `setCode` và `set_inflation_parameters` sau timelock (`pallet_scheduler`) để cộng đồng có thời gian phản ứng.
3. Lộ trình bỏ sudo hẳn, thay bằng quản trị on-chain, và công bố mốc thời gian.
4. Công bố địa chỉ ví sudo, reserve, treasury để ai cũng kiểm tra được số dư và vesting.

## 5. Lịch sử thay đổi

- spec_version 3: thêm `HARD_SUPPLY_CAP`, giới hạn 30 ngày cho `set_inflation_parameters`, test với tham số thật.
- spec_version 4: vá L2 (weight vừa một block, root khởi tạo, `data_hash`, cây Merkle 256 bit, `verify_strict`, `chain_id` trong chữ ký). Xem `L2_HUONG_DAN.md`.

## Changelog vòng 4 (không đổi runtime)
- Thêm hướng dẫn chuyển sudo sang multisig (`SUDO_MULTISIG.md`). Đây là biện pháp giảm rủi ro quản trị thực tế duy nhất ở thời điểm này vì sudo bỏ qua bộ lọc call.
- Chưa làm, cần quyết định của bạn: verifier SP1/Risc0 thật, benchmark weight, điều chỉnh phí / existential deposit theo giá PI, bridge.
