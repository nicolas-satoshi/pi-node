# PI Node

**A fixed-supply, community-first Layer 1 with a zero-knowledge rollup on the way.**

PI Node is the reference implementation of the **PI network**: a [Substrate](https://substrate.io) blockchain finalized by [AlephBFT](https://github.com/Cardinal-Cryptography/AlephBFT), with a hard supply cap of **28,000,000 PI**, predictable disinflationary issuance, and an experimental ZK-rollup (L2) layer designed around dual SP1 + Risc0 proofs.

> **Status: pre-launch / devnet.** The code is open for review and testing. It has not been independently audited and there is no live mainnet yet. Treat everything here as experimental until the checklist at the bottom is complete.

---

## Why PI?

| | |
|---|---|
| **Hard cap, enforced in code** | Total supply can never be configured above 28M PI. The cap is checked on-chain whenever issuance parameters change, not just promised in a doc. |
| **Inflation that fades out** | New PI is minted along an exponential curve that approaches the cap without ever touching it. Early validators are rewarded; late supply growth shrinks toward zero. |
| **Fast, final blocks** | 3-second blocks with AlephBFT finality. Once a block is finalized, it stays finalized. |
| **Tamper-resistant governance changes** | Inflation parameters can be changed at most once every 30 days, inside hard bounds, so nobody can quietly turn on the printing press. |
| **ZK rollup roadmap** | An L2 state-transition circuit with a sparse Merkle tree, strict Ed25519 signatures, replay protection and data-availability binding. Verification is fail-closed: a proof that can't be verified is rejected. |
| **Addresses that say `pi…`** | The network uses its own address prefix (`5297`), so your address starts with `pi`. |

---

## Tokenomics at a glance

- **Symbol:** PI
- **Genesis supply:** 7,000,000 PI
  - 6 genesis validators: 700,000 PI each (600,000 bonded)
  - Treasury: 1,800,000 PI
  - Reserve: 999,000 PI, vested linearly over 4 years
  - Sudo / operations: 1,000 PI
- **Hard cap:** 28,000,000 PI
- **Issuance:** exponential curve toward the cap, about 10-year time constant. Roughly 2M PI is minted in year one, and the rate falls every year after.
- **Split of new issuance:** 90% to validators and their stakers, 10% to the treasury. Nothing is minted once the cap is reached.

The full schedule, safety layers and known limits are in [TOKENOMICS.md](./TOKENOMICS.md).

---

## Network parameters

| Parameter | Value |
|---|---|
| Block time | 3 seconds |
| Session | 900 blocks (about 45 minutes) |
| Era | 32 sessions (about 24 hours) |
| Consensus | Aura block production + AlephBFT finality |
| Finality threshold | 2N/3 + 1 validators |
| Minimum validator bond | 100 PI |
| Minimum nominator bond | 10 PI |
| Unbonding period | 14 eras (about 14 days) |
| Address prefix (SS58) | 5297 (`pi…`) |

### Staking in one paragraph

Bond PI to become a validator or nominator and earn a share of each era's rewards. To leave: call `staking.chill()`, wait one era, call `staking.unbond(amount)`, wait 14 eras, then call `staking.withdrawUnbonded(0)` to move your PI back to your free balance. Skipping `chill` while your remaining bond would fall under the minimum fails with `InsufficientBond`.

---

## Build

You need a recent Rust toolchain (pinned in `rust-toolchain.toml`) and the WebAssembly target:

```bash
rustup target add wasm32-unknown-unknown
cargo build --release
```

This produces two binaries in `target/release/`:

- `pi-node-bin`: the node
- `pi-bootstrapper`: creates chain specs and validator keys

More detail, including system dependencies, is in [BUILD.md](./BUILD.md).

### Run the tests

```bash
cargo test -p pallet-zk-rollup-verifier -p pallet-aleph -p aleph-runtime
cd l2-guest && cargo test --features std --lib
```

The L2 guest lives outside the main workspace so it can be built for the zkVM targets on its own.

---

## Try it on your own machine

You don't need a server to see the chain running. `bootstrap_clean.sh` can start several validators on one computer (see "Example A" at the top of the script):

1. Generate two wallets (sudo and reserve) and keep their seeds offline:
   ```bash
   ./target/release/pi-node-bin key generate --scheme sr25519 --words 24
   ```
2. Put their addresses in `SUDO` and `RESERVE` at the top of `bootstrap_clean.sh`.
3. Run the script and follow the instructions it prints.

Then connect with [Polkadot-JS Apps](https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944) pointed at `ws://127.0.0.1:9944`.

Running a public node later? Use `bootstrap_clean.sh` rather than the older `setup_6val_*.sh` scripts. It sends each host only the keys that host needs, keeps seeds on your local machine, and runs nodes as an unprivileged user.

---

## Security model, honestly

- **Sudo:** the chain currently has a sudo key. It can upgrade the runtime and spend the treasury, so it is the most sensitive key in the network. The plan is to move it to a multisig. See [SUDO_MULTISIG.md](./SUDO_MULTISIG.md) and `scripts/derive_multisig.py`.
- **L2 verifier:** the SP1/Risc0 verification path is fail-closed and not live. The L2 sequencer in `l2-guest` is a reference implementation, and the L1↔L2 bridge is a design only ([L2_BRIDGE_DESIGN.md](./L2_BRIDGE_DESIGN.md)). Don't put real value on L2.
- **Audit:** no third-party audit has been done. Please don't treat the contents of this repository as production-ready.

Found a vulnerability? Please report it privately to the maintainers before opening a public issue.

---

## Roadmap

- [x] Hard supply cap and bounded inflation controls
- [x] Rollup state commitment bound to chain ID, batch index and data hash
- [x] Reference L2 sequencer with witness builder
- [ ] Real SP1 and Risc0 verifiers in the runtime
- [ ] Benchmarked weights and fee tuning
- [ ] Sudo moved to multisig, then to on-chain governance
- [ ] L1↔L2 bridge (deposit and withdraw)
- [ ] Independent security audit
- [ ] Public testnet, then mainnet

---

## Join in

PI gets better the more people run it, break it and improve it.

- **Run a node** on your own machine and tell us what felt rough.
- **Review the code**, especially `pallets/aleph`, `pallets/zk-rollup-verifier` and `l2-guest`.
- **Break the tokenomics:** try to push supply past the cap. The tests in `bin/runtime` and `pallets/aleph` are a good place to start.
- **Write docs or tools**, such as wallets, explorers and guides.
- **Open a pull request.** Fork the repository, make your change, and submit it. All pull requests are welcome.

Some documents ([L2_HUONG_DAN.md](./L2_HUONG_DAN.md), [SUDO_MULTISIG.md](./SUDO_MULTISIG.md), [L2_BRIDGE_DESIGN.md](./L2_BRIDGE_DESIGN.md)) are currently written in Vietnamese. Translations are very welcome.

---

## Credits

PI Node is a fork of [aleph-node](https://github.com/Cardinal-Cryptography/aleph-node) by Cardinal Cryptography and the Aleph Zero Foundation, built on [Substrate](https://substrate.io) and the [AlephBFT](https://arxiv.org/abs/1908.05156) consensus protocol. Thanks to everyone behind those projects.

## License

- All crates under the `bin` directory are licensed under the GNU GPL version 3.
- All other crates are licensed under the Apache License 2.0.
