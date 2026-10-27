# Chuyển quyền sudo sang multisig

Hiện tại một khoá sudo duy nhất có thể: chỉnh tham số lạm phát (trong giới hạn
cứng của spec 4), nâng cấp runtime, chi quỹ treasury, đổi sequencer L2. Mất hoặc
lộ khoá đó là mất toàn bộ quyền kiểm soát chain. Multisig N-của-M giảm rủi ro
này: cần nhiều khoá đồng ý, và mất một khoá không làm mất chain.

> Lưu ý kỹ thuật: `pallet_sudo` bỏ qua bộ lọc call, nên KHÔNG thể giới hạn sudo
> bằng cấu hình runtime. Multisig là cách giảm rủi ro thực tế duy nhất ở tầng
> quản trị hiện tại. Về lâu dài nên thay sudo bằng quản trị on-chain (xem
> TOKENOMICS.md).

## Chọn ngưỡng
- 2-của-3: tối thiểu. Mất 2 khoá là mất quyền vĩnh viễn.
- 3-của-5: khuyến nghị khi đã có đủ người đáng tin. Chịu được mất 2 khoá.
- Mỗi khoá nằm trên một thiết bị/người KHÁC NHAU. Ba khoá cùng một máy thì
  không an toàn hơn một khoá.

## Các bước (không bước nào bỏ qua được)

1. **Tạo khoá** cho từng người ký, mỗi người tự tạo trên máy của mình. Chỉ gửi
   cho nhau ĐỊA CHỈ công khai, không bao giờ gửi seed.
2. **Tính địa chỉ multisig** (chạy offline được, chỉ cần Python 3):
   ```
   python3 scripts/derive_multisig.py --threshold 2 ADDR1 ADDR2 ADDR3
   ```
   Mặc định dùng prefix 5297 (địa chỉ bắt đầu bằng `pi`). Script tự chạy
   self-test với vector chuẩn trước khi in kết quả. Mọi người ký tự chạy và
   đối chiếu cùng một kết quả. Thứ tự địa chỉ không ảnh hưởng.
3. **Đối chiếu trên giao diện**: trong Polkadot-JS Apps, Accounts → Add
   multisig, nhập cùng danh sách và ngưỡng. Địa chỉ phải trùng với bước 2.
4. **Nạp một ít PI** vào địa chỉ multisig (đủ trả existential deposit và phí).
5. **Thử trước với call vô hại**: từ một người ký, gửi
   `multisig.asMulti(threshold, otherSignatories, null, system.remark("test"), maxWeight)`,
   các người còn lại duyệt. Chỉ khi thử xong và thấy `MultisigExecuted`
   mới sang bước 6.
6. **Chuyển sudo**: từ khoá sudo hiện tại gọi `sudo.setKey(địa_chỉ_multisig)`.
   KHÔNG THỂ HOÀN TÁC nếu địa chỉ sai hoặc multisig không dùng được. Hãy đọc
   lại địa chỉ từng ký tự một lần nữa.
7. **Xác nhận**: `sudo.key()` phải trả về địa chỉ multisig. Thử một thao tác sudo
   rủi ro thấp qua multisig.
8. **Huỷ khoá sudo cũ** khi đã chắc chắn, và đừng giữ lại seed của nó.

## Dùng sudo sau khi chuyển
Khoá sudo bây giờ là địa chỉ multisig, nên mọi thao tác sudo đi qua:
`multisig.asMulti(threshold, others, timepoint, sudo.sudo(<call>), maxWeight)`.
Người khởi tạo gửi call lần đầu (lưu `timepoint` từ sự kiện `NewMultisig`),
những người còn lại gọi lại với timepoint đó; người cuối cùng làm call được
thực thi. Có thể dùng `multisig.approveAsMulti` với hash của call để tiết kiệm
phí cho các lần duyệt giữa chừng.

## Rủi ro còn lại
- Người ký bị thoả hiệp đủ ngưỡng vẫn kiểm soát được chain.
- Mất đủ khoá để không đạt ngưỡng thì không ai nâng cấp hay sửa runtime được.
  Lưu bản sao lưu seed ngoại tuyến cho từng khoá.
- Phí và deposit của multisig tính theo `DepositBase`/`DepositFactor` trong
  runtime; nạp dư một chút.
