# Thiết kế bridge L1 ↔ L2 (CHỈ LÀ THIẾT KẾ, CHƯA CÓ CODE)

Trạng thái hiện nay: L2 chưa có cách đưa PI vào hay ra. Số dư L2 chỉ do
`StateTree::set_account` tạo (genesis), nên L2 hiện là một sổ cái kín, chưa gắn
với token thật. Tài liệu này mô tả điều cần xây trước khi L2 giữ giá trị thật.

## Bất biến phải luôn đúng
```
tổng số dư trong cây L2  ≤  PI đang bị khoá trong tài khoản bridge trên L1
```
Mọi lỗi làm bất biến này sai đều là lỗi in tiền. Vì vậy mọi thay đổi tổng cung
L2 chỉ được đến từ sự kiện L1 đã được chứng minh.

## Nạp tiền (deposit, L1 → L2)
1. Người dùng gọi extrinsic L1 `deposit(l2_account: [u8;32], amount)`; pallet
   chuyển `amount` vào tài khoản bridge và ghi vào hàng đợi
   `Deposits[deposit_id] = (l2_account, amount)`.
2. Batch L2 có loại giao dịch mới `Deposit { deposit_id }`. Public values của
   batch commit thêm `deposits_hash` (hash của các deposit đã tiêu thụ, theo thứ
   tự). Pallet L1 chỉ chấp nhận batch nếu `deposits_hash` khớp đúng đầu hàng đợi.
3. Guest cộng số dư và KHÔNG cho tiêu thụ cùng một deposit hai lần (id tăng đơn
   điệu, nằm trong public values).

## Rút tiền (withdraw, L2 → L1)
1. Người dùng ký giao dịch L2 `Withdraw { l1_account, amount, nonce }`, guest trừ
   số dư và đưa vào danh sách rút của batch.
2. Public values commit `withdrawals_root` (Merkle root các lệnh rút). Pallet L1
   lưu root theo `batch_index`.
3. Người dùng gọi L1 `claim_withdrawal(batch_index, proof, l1_account, amount)`;
   pallet kiểm Merkle proof, đánh dấu đã nhận (chống nhận hai lần) và chuyển PI
   từ tài khoản bridge.
4. Giữa chứng minh batch và cho nhận tiền nên có độ trễ (cửa sổ thử thách) để
   kịp phát hiện sự cố khi verifier còn mới.

## Điều kiện tiên quyết
- Verifier SP1/Risc0 thật chạy được (hiện fail-closed, từ chối mọi proof). Không
  có verifier thật thì bridge vô nghĩa vì bất kỳ ai cũng không thể hoàn tất batch.
- Giới hạn tổng số PI được nạp ban đầu (ví dụ trần theo từng ngày) để lỗi chưa
  biết có thiệt hại giới hạn.
- Cơ chế thoát khẩn cấp: nếu sequencer ngừng hoạt động, người dùng vẫn rút được
  theo trạng thái batch cuối đã chứng minh (forced exit).
- Thêm vào `RollupStateCommitment` cần nâng `COMMITMENT_VERSION` (hiện 3) và
  nâng `spec_version`.

## Việc cần quyết
- Mô hình sequencer: một sequencer do bạn chạy (đơn giản, tập trung) hay nhiều.
- Có cho phép rút ngay không, hay luôn có cửa sổ thử thách.
- Trần nạp tiền theo từng giai đoạn.
