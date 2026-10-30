# Moving sudo to a multisig

Today a single sudo key can: adjust the inflation parameters (within the hard
bounds of spec 4), upgrade the runtime, spend the treasury, and change the L2
sequencer. Losing or leaking that key means losing all control of the chain.
An N-of-M multisig reduces this risk: several keys must agree, and losing one
key does not mean losing the chain.

> Technical note: `pallet_sudo` bypasses call filters, so sudo can NOT be
> restricted through runtime configuration. A multisig is the only practical
> way to reduce risk at the current governance layer. In the long run, sudo
> should be replaced by on-chain governance (see TOKENOMICS.md).

## Choosing a threshold
- 2-of-3: the minimum. Losing 2 keys means permanently losing control.
- 3-of-5: recommended once you have enough trusted people. It tolerates the
  loss of 2 keys.
- Each key must live on a DIFFERENT device and belong to a DIFFERENT person.
  Three keys on the same machine are no safer than one key.

## Steps (none of them can be skipped)

1. **Generate keys** for each signatory. Everyone generates their own key on
   their own machine. Only exchange the public ADDRESSES, never the seed.
2. **Derive the multisig address** (works offline, only Python 3 is needed):
   ```
   python3 scripts/derive_multisig.py --threshold 2 ADDR1 ADDR2 ADDR3
   ```
   It uses prefix 5297 by default (addresses start with `pi`). The script
   runs a self-test against a known test vector before printing the result.
   Every signatory should run it independently and compare results. The order
   of the addresses does not matter.
3. **Cross-check in the UI**: in Polkadot-JS Apps, go to Accounts → Add
   multisig, and enter the same list of signatories and the same threshold.
   The address must match the one from step 2.
4. **Fund the multisig address** with a small amount of PI (enough for the
   existential deposit and fees).
5. **Test with a harmless call first**: from one signatory, submit
   `multisig.asMulti(threshold, otherSignatories, null, system.remark("test"), maxWeight)`,
   and have the other signatories approve it. Only move on to step 6 once the
   test is done and you have seen `MultisigExecuted`.
6. **Transfer sudo**: from the current sudo key, call
   `sudo.setKey(multisig_address)`. This CANNOT BE UNDONE if the address is
   wrong or the multisig is unusable. Re-read the address character by
   character one more time.
7. **Verify**: `sudo.key()` must return the multisig address. Try a low-risk
   sudo operation through the multisig.
8. **Retire the old sudo key** once you are certain everything works, and do
   not keep its seed.

## Using sudo after the transfer
The sudo key is now the multisig address, so every sudo operation goes through:
`multisig.asMulti(threshold, others, timepoint, sudo.sudo(<call>), maxWeight)`.
The initiator submits the call first (save the `timepoint` from the
`NewMultisig` event). The other signatories then call it again with that
timepoint, and the last signatory's call is the one that executes. You can use
`multisig.approveAsMulti` with the call hash to save fees on the intermediate
approvals.

## Remaining risks
- If enough signatories to reach the threshold are compromised, they still
  control the chain.
- If enough keys are lost that the threshold can no longer be reached, nobody
  can upgrade or fix the runtime. Keep an offline backup of each key's seed.
- Multisig fees and deposits are computed from `DepositBase` / `DepositFactor`
  in the runtime; fund the account with a little extra.
