# Signature primitives

Provider-neutral Rust mechanisms for reading and validating digital-signature
formats. Applications retain control over cryptographic providers, trust policy,
resource budgets and external data acquisition.

## Packages

| Package | Contract |
| --- | --- |
| `structured-asn1` | Borrowed BER/DER values, exact byte ranges and shared parsing budgets |
| `structured-pkix` | Borrowed X.509 certificates and provider-neutral path validation |

The packages are being extracted and are not yet published. CMS,
timestamp and XML advanced-signature mechanisms will be listed here when their
standalone contracts and consumer integrations are verified.

## Development

Run `cargo nextest run --workspace`, `cargo test --workspace --doc`, and
`cargo clippy --workspace --all-targets -- -D warnings`.
Check alloc-only builds using `cargo check --workspace --no-default-features`
and the `wasm32-unknown-unknown` and `thumbv7em-none-eabihf` targets.
Verify distributable archives with `bash scripts/check-packages.sh`; it uses
fresh temporary package state so earlier same-version workspace archives cannot
substitute stale source during verification.

Mechanism processing admits allocation capacity and input-dependent work through
an explicit shared `Memory`. Owned results retain their storage charge until
deallocation. Raw byte views and ordinary Rust formatting/equality traits leave
caller-owned traversal and output storage to the application. Injected crypto
and recognizer implementations must admit their own work and allocations using
the supplied execution domain; passing that domain does not bound arbitrary
external callback code.

## License

Apache-2.0. Contributions are accepted under the
[Structured World Contributor License Agreement](https://sw.foundation/cla);
see [CONTRIBUTING.md](CONTRIBUTING.md).
