# Emergency freeze design

## Goal

Provide a single shared switch that can halt every composed compliance check in one transaction during an incident, without requiring each individual primitive contract to be paused independently.

## Proposed mechanism

Introduce a small shared `circuit-breaker` contract with three operations:

- `initialize(admin)` sets the administrative key once.
- `freeze(admin)` flips the breaker to the frozen state.
- `unfreeze(admin)` restores normal operation.

Composed consumers should check the breaker first, before any per-contract compliance check or balance mutation. In this repository, the reference consumer example now resolves the breaker address during initialization and calls `is_frozen()` before proceeding with the denylist gate check and transfer.

## Who can trigger freeze

Trust is asymmetric, matching fail-closed incident-response convention: halting is cheap and should be fast, while resuming is deliberate and should be hard.

- **Freeze** is callable by the admin **or any guardian**. A guardian is an address in a freeze-only set that the admin manages via `add_guardian(admin, guardian)` and `remove_guardian(admin, guardian)`. `is_guardian(address)` reads membership. Guardians can freeze but cannot unfreeze, change guardians, or rotate the admin.
- **Unfreeze** is **admin-only**. A guardian that froze the system cannot reopen it, so a compromised or mistaken guardian can stop flows but cannot restore them on its own.
- Guardian and admin authorization both go through `require_auth()`, so a guardian freeze is an ordinary signed transaction from that guardian's key.

This means the admin key is no longer the only key that can react during an incident: if it is unavailable, any guardian can still halt the breaker. The admin still controls the guardian set, so guardian keys should be issued and revoked with the same care as the admin key itself. A multisig or threshold admin remains the recommended production setup; the guardian set complements it rather than replacing it.

## How quickly a consumer checks it

The breaker adds one extra cross-contract call to every gated transfer. In Soroban that is a small but real extra cost: the consumer resolves the breaker address, builds a client, and performs a read-only `is_frozen()` call before it reaches any internal balance mutation. This is still fast enough for an emergency stop because the check happens before the transfer path touches state. In practice, the added cost is a single contract call plus a small amount of storage access, which is materially cheaper than allowing a transfer to proceed and then trying to unwind it later.

## Unfreeze process

Unfreeze is intentionally separate from freeze. The admin can re-enable the system after incident review, and the consumer immediately resumes its normal path once the breaker reports `false`.

## Why this fits the current repo

This pattern composes well with the existing primitives:

- the breaker becomes the shared incident switch;
- each contract or consumer can still honor its own local pause mechanism if it exists later;
- the consumer can fail closed quickly by checking the breaker before other compliance logic.

This keeps the implementation small and reviewable while still giving issuers the operational control they need during a live incident.
