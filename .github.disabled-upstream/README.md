# Workflow CI/CD của upstream (aleph-node) — đã tắt

Các file trong `workflows/` là của dự án gốc: chúng build/đẩy image, deploy mainnet/testnet
của Aleph Zero, dùng secret và hạ tầng AWS/ECR của họ. Chúng không chạy được trên `pi-node`
và nếu cấu hình sai có thể cố đẩy lên hạ tầng không phải của bạn, nên đã bị chuyển ra khỏi
`.github/workflows` (GitHub chỉ chạy workflow ở đúng đường dẫn đó).

Muốn dùng CI: viết workflow mới trong `.github/workflows/` chỉ gồm
`cargo fmt --check`, `cargo test -p pallet-zk-rollup-verifier -p pallet-aleph -p aleph-runtime`
và `cd l2-guest && cargo test --features std --lib`. Đừng copy nguyên các file deploy.
