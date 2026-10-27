#!/usr/bin/env python3
"""Tính địa chỉ multisig (pallet_multisig) từ danh sách người ký và ngưỡng.

Dùng để chuyển khoá sudo sang multisig: tính địa chỉ, kiểm tra bằng mắt trên
polkadot.js (Developer > Extrinsics > multisig), rồi mới gọi `sudo.setKey`.

    python3 scripts/derive_multisig.py --threshold 2 ADDR1 ADDR2 ADDR3 [--prefix 5297]

Địa chỉ đầu vào có thể ở bất kỳ ss58 prefix nào. Thứ tự đầu vào không quan trọng
(pallet sắp xếp theo public key). Chỉ dùng thư viện chuẩn của Python.

Công thức (pallet_multisig::Pallet::multi_account_id):
    blake2_256( b"modlpy/utilisuba" ++ SCALE(Vec<AccountId32> đã sắp xếp) ++ threshold(u16 LE) )
Đã đối chiếu với vector chuẩn: Alice/Bob/Charlie, ngưỡng 2, prefix 42
→ 5DjYJStmdZ2rcqXbXGX7TW85JsrW6uG4y9MUcLq2BoPMpRA7 (xem --self-test).
"""
import argparse
import hashlib
import sys

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in ALPHABET:
            raise ValueError(f"ký tự không hợp lệ trong địa chỉ: {c!r}")
        n = n * 58 + ALPHABET.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = ALPHABET[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + s


def ss58_checksum(payload: bytes) -> bytes:
    return hashlib.blake2b(b"SS58PRE" + payload, digest_size=64).digest()[:2]


def ss58_decode(addr: str) -> bytes:
    raw = b58decode(addr)
    if len(raw) == 35:  # prefix 1 byte + 32 + checksum 2
        payload, checksum, pub = raw[:-2], raw[-2:], raw[1:33]
    elif len(raw) == 36:  # prefix 2 byte
        payload, checksum, pub = raw[:-2], raw[-2:], raw[2:34]
    else:
        raise ValueError(f"độ dài địa chỉ lạ ({len(raw)} byte): {addr}")
    if ss58_checksum(payload) != checksum:
        raise ValueError(f"checksum sai, địa chỉ bị gõ nhầm?: {addr}")
    return pub


def ss58_encode(pub: bytes, prefix: int) -> str:
    if prefix < 64:
        payload = bytes([prefix]) + pub
    else:
        payload = bytes([((prefix & 0xFC) >> 2) | 0x40, (prefix >> 8) | ((prefix & 0x03) << 6)]) + pub
    return b58encode(payload + ss58_checksum(payload))


def compact_len(n: int) -> bytes:
    if n < 64:
        return bytes([n << 2])
    if n < 2**14:
        return ((n << 2) | 1).to_bytes(2, "little")
    raise ValueError("quá nhiều người ký")


def multi_account_id(pubs, threshold: int) -> bytes:
    who = sorted(pubs)
    if len(set(who)) != len(who):
        raise ValueError("có người ký trùng nhau")
    if not 1 <= threshold <= len(who):
        raise ValueError("ngưỡng phải nằm trong [1, số người ký]")
    data = b"modlpy/utilisuba" + compact_len(len(who)) + b"".join(who) + threshold.to_bytes(2, "little")
    return hashlib.blake2b(data, digest_size=32).digest()


def self_test() -> None:
    alice = bytes.fromhex("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
    bob = bytes.fromhex("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48")
    charlie = bytes.fromhex("90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22")
    got = ss58_encode(multi_account_id([alice, bob, charlie], 2), 42)
    want = "5DjYJStmdZ2rcqXbXGX7TW85JsrW6uG4y9MUcLq2BoPMpRA7"
    assert got == want, f"self-test FAIL: {got} != {want}"
    assert ss58_decode(ss58_encode(alice, 5297)) == alice
    print("self-test OK")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("addresses", nargs="*")
    ap.add_argument("--threshold", type=int)
    ap.add_argument("--prefix", type=int, default=5297, help="ss58 prefix của chain (mặc định 5297 = 'pi...')")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return
    if not args.addresses or args.threshold is None:
        ap.error("cần --threshold và ít nhất một địa chỉ")

    self_test()  # luôn tự kiểm tra công thức trước khi in kết quả
    pubs = [ss58_decode(a) for a in args.addresses]
    ms = multi_account_id(pubs, args.threshold)
    print(f"Người ký : {len(pubs)}  ngưỡng: {args.threshold}")
    print(f"Multisig : {ss58_encode(ms, args.prefix)}   (prefix {args.prefix})")
    print(f"Generic  : {ss58_encode(ms, 42)}   (prefix 42)")
    print(f"Hex      : 0x{ms.hex()}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, AssertionError) as e:
        sys.exit(f"Lỗi: {e}")
