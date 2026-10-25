# compliance-integration-flow

Integration example showing how a jurisdiction policy, an emergency circuit
breaker, multisig administration, and an audit log fit into one transfer
decision. Unlike [`rwa-compliance-flow`](../rwa-compliance-flow), which
demonstrates the allowlist/denylist/jurisdiction checks together, this example
uses `policy-engine` to evaluate jurisdiction rules, checks the circuit breaker
first, and records each outcome in `audit-log`. It is a contract-composition
example, not a deployable RWA token like [`rwa-token`](../rwa-token).

## Primitives used

- `jurisdiction-flag` — stores jurisdiction codes for addresses.
- `policy-engine` — evaluates whether both transfer parties satisfy the
  configured jurisdiction check.
- `compliance-aggregator` — provides an independent per-address check in the
  integration tests.
- `multisig-admin` — administers the circuit breaker.
- `circuit-breaker` — halts the transfer flow before policy evaluation.
- `audit-log` — records allowed, blocked, and halted outcomes.
- `pausable` — used internally by `jurisdiction-flag`.

The flow is intentionally scoped to these components; it does not compose
`allowlist-token` or `denylist-gate`.

## Run

From the repository root:

```sh
cargo test -p compliance-integration-flow
cargo build -p compliance-integration-flow --target wasm32v1-none --release
```

## Expected output

The test command should finish successfully with three passing integration
tests. They cover an allowed transfer, a transfer rejected by the jurisdiction
policy, and a circuit-breaker halt; each outcome is checked in the audit log.
The build command should produce the example contract's Wasm artifact under
`target/wasm32v1-none/release/`.
