# rwa-token

Reference RWA-style token that composes all three compliance primitives in
one `transfer` path:

| Order | Check | Primitive | Failure |
| --- | --- | --- | --- |
| 1 | Both parties allowlisted | [`allowlist-token`](../../contracts/allowlist-token).`is_allowed` | `Error::NotAllowlisted` |
| 2 | Neither party denylisted | [`denylist-gate`](../../contracts/denylist-gate).`check` | `Error::DeniedByGate` |
| 3 | Both parties permitted | [`jurisdiction-flag`](../../contracts/jurisdiction-flag).`is_permitted_jurisdiction` | `Error::JurisdictionNotPermitted` |

Checks are fail-fast and return a dedicated error so integrators can tell
which gate blocked the transfer.

## Pattern

Same as [`denylist-gate-consumer`](../denylist-gate-consumer): this crate
does **not** link the primitive crates' `#[contractimpl]` exports into its
wasm. It only depends on them as `dev-dependencies` for tests, and uses
`#[contractclient]` traits (`AllowlistInterface`, `DenylistGateInterface`,
`JurisdictionFlagInterface`) for cross-contract calls.

`allowlist-token` is used here purely as the on-chain allowlist source via
`is_allowed` — the example token keeps its own balances rather than
forwarding through `allowlist-token.transfer`.

This is the restricted custom-token pattern: `RwaToken::transfer` checks the
allowlist, denylist, and jurisdiction gates before mutating its own balances.
Calling this token's `transfer` directly still runs those checks. It does not
demonstrate wrapping an unrestricted SEP-41 token; a wrapper deployment must
also prevent users from transferring the underlying asset directly. SAC
`AUTH_REQUIRED`/`AUTH_REVOCABLE` flags alone do not provide that caller
restriction.

## Build & test

```sh
cargo test -p rwa-token
cargo build -p rwa-token --target wasm32v1-none --release
```

## Testnet

See [TESTNET.md](./TESTNET.md) for the reference deployment, walkthrough
transactions, and how to redeploy after a testnet reset.
