# PI Tokenomics: supply, inflation and governance powers

This document describes exactly what the source code implements. If the code
changes, this document must be updated.

## 1. Genesis allocation (total 7,000,000 PI)

| Group | Amount (PI) | Share | Notes |
|---|---:|---:|---|
| 6 genesis validators (6 × 700,000) | 4,200,000 | 60.0% | Each wallet starts with 600,000 PI already bonded |
| Treasury | 1,800,000 | 25.7% | Only sudo can move it (see section 4) |
| Reserve wallet | 999,000 | 14.3% | Linear vesting over 4 years, starting at block 0 |
| Sudo wallet | 1,000 | 0.0% | Just enough to pay fees |

`bin/chain-bootstrapper` checks the total with `assert_eq!` when it generates
the chain spec.

## 2. Issuance schedule

Every era (1 day = 32 sessions × 900 blocks × 3 seconds), the runtime mints:

    mint = (1 − e^(−era/horizon)) × (cap − current_total_supply)

- `cap` defaults to 28,000,000 PI and `horizon` defaults to 10 years.
- 90% of the minted amount goes to validators (and nominators), 10% goes to the treasury.
- The amount minted does **not** depend on how much PI is staked, so a staker's APR depends on the total stake.
- Nothing is burned: transaction fees and slashes both flow into the treasury (`Burn = 0%`).
- Total supply approaches 28 million PI asymptotically and never reaches it.

| Year | Minted (million PI) | Inflation per year | Total supply at end of year (million PI) | Staker APR (3.6 million PI staked) |
|---:|---:|---:|---:|---:|
| 1 | 2.00 | 28.5% | 9.00 | 50.0% |
| 2 | 1.81 | 20.1% | 10.81 | 45.2% |
| 3 | 1.64 | 15.1% | 12.44 | 40.9% |
| 5 | 1.34 | 9.6% | 15.26 | 33.5% |
| 10 | 0.81 | 4.2% | 20.27 | 20.3% |
| 20 | 0.30 | 1.2% | 25.16 | 7.5% |
| 30 | 0.11 | 0.4% | 26.95 | 2.7% |

The figures above are verified by the tests `pi_first_year_mint_matches_published_schedule`
and `pi_thirty_year_supply_stays_below_cap` in `bin/runtime/src/lib.rs`.

## 3. Layers protecting the supply cap

1. **Self-clamping mint formula**: total supply after minting never exceeds `AzeroCap`; if supply is equal to or above the cap, the mint is zero.
2. **Absolute ceiling `HARD_SUPPLY_CAP` = 28,000,000 PI** (`primitives/src/lib.rs`, a constant in the runtime code).
   `set_inflation_parameters` rejects any `azero_cap` larger than it.
3. **Rate limit**: two successful `set_inflation_parameters` calls must be at least
   `MIN_INFLATION_PARAMS_CHANGE_INTERVAL` = 864,000 blocks (30 days) apart.
4. **Per-call bounds** (inherited from upstream): the distance to the cap can only change within [½×, 2×]; `horizon` within [½×, 2×].

Before this version (spec_version 2), layers 2 and 3 did not exist: five consecutive calls were enough to raise the cap from 28 million to about 679 million PI.

## 4. Remaining limits: these must be disclosed clearly

The following points are **not** resolved in code, and the project should not be advertised as "trustless" or as having a "hard cap that cannot be changed":

- **Sudo has root power.** `pallet_sudo` executes calls with `dispatch_bypass_filter`, so
  `BaseCallFilter` (SafeMode/TxPause) does **not** constrain sudo. Sudo can:
  - upgrade the runtime with `System.setCode`, including removing `HARD_SUPPLY_CAP` (though this is public and visible on-chain);
  - set balances / force transfers (the `Balances` extrinsics reserved for Root);
  - write arbitrary storage (`System.setStorage`) and move treasury funds.
- **The treasury is controlled by sudo**: `ApproveOrigin`/`RejectOrigin` is the sudo key, and public spending proposals are disabled (extremely high bond).
- **Concentration**: about 86% of the genesis supply (validators + treasury) sits in accounts operated by the same party.
- **No L2 bridge**: the `zk-rollup-verifier` pallet does not touch `Balances`. When deposit/withdraw is added, it must preserve the invariant
  "total L2 balances ≤ PI locked on L1".

### Governance recommendations (outside the scope of the code)

1. Move the sudo key to a multisig (for example 3-of-5, with independent parties) before any real value is at stake.
2. Put `setCode` and `set_inflation_parameters` behind a timelock (`pallet_scheduler`) so the community has time to react.
3. Publish a roadmap for removing sudo entirely and replacing it with on-chain governance, with dates.
4. Publish the sudo, reserve and treasury wallet addresses so anyone can check balances and vesting.

## 5. Change history

- spec_version 3: added `HARD_SUPPLY_CAP`, the 30-day limit on `set_inflation_parameters`, and tests with the real parameters.
- spec_version 4: L2 fixes (weight fits in one block, root initialization, `data_hash`, 256-bit Merkle tree, `verify_strict`, `chain_id` in the signature). See `L2_HUONG_DAN.md`.

## Changelog, round 4 (no runtime change)
- Added a guide for moving sudo to a multisig (`SUDO_MULTISIG.md`). This is the only practical governance risk reduction available right now, because sudo bypasses the call filter.
- Not done yet, needs your decision: real SP1/Risc0 verifiers, weight benchmarks, fee / existential deposit tuning against the PI price, and the bridge.
