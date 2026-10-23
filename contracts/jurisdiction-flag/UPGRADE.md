# Jurisdiction-Flag Contract Upgrade Mechanism

## Overview

WASM upgrades are issuer-controlled and timelocked. The immediate `upgrade()`
entry point has been removed. Every proposal must wait at least
`MIN_UPGRADE_DELAY_LEDGERS` (17,280 ledgers, approximately one day at five
seconds per ledger) before it can be committed.

## Upgrade Flow

1. Upload the replacement Wasm and record its hash.
2. The issuer calls `propose_upgrade(issuer, new_wasm_hash, delay_ledgers)`.
	`delay_ledgers` must be at least `MIN_UPGRADE_DELAY_LEDGERS`; a new proposal
	replaces any existing proposal.
3. Monitor the proposal during the delay. The issuer can call
	`cancel_upgrade(issuer)` to discard it.
4. Once the current ledger sequence reaches `activated_at`, the issuer calls
	`commit_upgrade(issuer)`. The contract installs the proposed Wasm and clears
	the pending proposal.

All three functions require the current issuer. A compliance officer cannot
propose, commit, or cancel an upgrade. `propose_upgrade` emits the compact
`upgprop` event and `commit_upgrade` emits `upgcommit`; cancellation emits no
event.

## Storage Compatibility

Soroban preserves instance and persistent storage when replacing Wasm. The
issuer and jurisdiction mappings therefore survive as long as their storage
keys and value shapes remain compatible. `PendingUpgrade` is an appended
instance-storage key; adding it does not change the keys used by existing
deployments.

If a future release needs a breaking schema change, it must provide and
document an explicit migration path before the upgrade ships. See
[`STORAGE_VERSIONING.md`](../../STORAGE_VERSIONING.md) for the project-wide
policy.

## Security Model

The enforced minimum delay gives issuer operators and external observers a
review window, and the issuer can cancel a malicious or mistaken proposal.
The window does not independently block a compromised issuer: if no authorized
issuer cancels the proposal, it can still be committed after the delay. Use a
monitored issuer key or a multisig issuer wrapper where stronger controls are
required. See J6 in the [threat model](../../docs/THREAT_MODEL.md).

Soroban does not retain an automatic rollback target. A faulty committed
upgrade must be corrected by uploading a fixed Wasm and proposing another
upgrade, which is subject to the same minimum delay.

## Testing the Upgrade Path

The contract tests cover issuer-only authorization, rejection below the
minimum delay, acceptance at the minimum, early-commit rejection, and
cancellation. Before a production upgrade, rehearse the complete upload,
proposal, monitoring, cancellation/commit, and post-upgrade storage checks on
testnet.

## Future Enhancements

1. Add a dedicated storage migration function if a breaking schema change is
	ever required.
2. Consider routing issuer upgrade authority through multisig governance.

## References

- Soroban Host Function: `update_current_contract_wasm` ([Soroban SDK docs](https://docs.rs/soroban-sdk/latest/soroban_sdk/struct.Deployer.html#method.update_current_contract_wasm))
- Storage Model: [Soroban Storage](https://soroban.stellar.org/docs/learn/storing-data)
