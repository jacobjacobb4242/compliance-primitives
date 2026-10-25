# jurisdiction-flag

An issuer-controlled mapping from addresses to jurisdiction codes.

| Method | Purpose |
| --- | --- |
| `initialize(issuer)` | Configure the issuer. |
| `get_issuer() -> Address` | Read the configured issuer. |
| `set_jurisdiction(issuer, address, code)` | Set or replace an address jurisdiction. |
| `get_jurisdiction(address)` | Read the current code and expiry state. |
| `is_permitted_jurisdiction(address, allowed_codes) -> bool` | Read whether an address matches an allowed code. |
