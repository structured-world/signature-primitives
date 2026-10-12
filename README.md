# Signature primitives

Provider-neutral Rust mechanisms for reading and validating digital-signature
formats. Applications retain control over cryptographic providers, trust policy,
resource budgets and external data acquisition.

## Packages

| Package | Contract |
| --- | --- |
| `structured-asn1` | Borrowed BER/DER values, exact byte ranges and shared parsing budgets |
| `structured-pkix` | Borrowed X.509 certificates and provider-neutral path validation |

Both packages are published on crates.io with a shared workspace version. CMS,
timestamp and XML advanced-signature mechanisms will be listed here when their
standalone contracts and consumer integrations are verified.

## Releases

`structured-asn1` and `structured-pkix` use one release-plz version group.
Release-plz prepares a version/changelog PR using the organization release bot;
merging that PR publishes the packages after CI succeeds on its exact main commit.
Dependencies are published before their dependants. Git tags and release notes
retain each package's name, even though both packages share their version.

Registry publishing uses OIDC, bound to this repository, `release-plz.yml` and
the `release` environment. No long-lived crates.io token is stored in GitHub.
The workflow's default manual run verifies token exchange without uploading
a new version. First-time publication of a new package still requires an owner
to bootstrap it and register its trusted publisher on crates.io.

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
