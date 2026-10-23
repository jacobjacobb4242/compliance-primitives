# jurisdiction-flag

An issuer-controlled mapping from addresses to jurisdiction codes.

| Method | Purpose |
| --- | --- |
| `initialize(issuer)` | Configure the issuer. |
| `set_jurisdiction(issuer, address, code)` | Set or replace an address jurisdiction. |
| `set_jurisdiction_until(issuer, address, code, valid_until)` | Set or replace a jurisdiction with an inclusive ledger expiry. |
| `add_jurisdiction(issuer, address, code)` | Add a jurisdiction code without replacing existing codes. |
| `set_multiple_jurisdictions(caller, entries)` | Set codes for multiple addresses; issuer or compliance officer may call. |
| `propose_upgrade(issuer, new_wasm_hash, delay_ledgers)` | Propose an issuer-only upgrade with at least 17,280 ledgers of delay. |
| `commit_upgrade(issuer)` | Commit a pending upgrade after its delay. |
| `cancel_upgrade(issuer)` | Cancel a pending upgrade proposal. |
| `get_jurisdiction(address)` | Read the current code and expiry state. |
| `is_permitted_jurisdiction(address, allowed_codes) -> bool` | Read whether an address matches an allowed code. |

The compliance officer can also call `set_jurisdiction`,
`set_jurisdiction_until`, `add_jurisdiction`, and
`set_multiple_jurisdictions`. Removal, pause, issuer management, and upgrade
operations remain issuer-only. The immediate `upgrade` entry point has been
removed.
