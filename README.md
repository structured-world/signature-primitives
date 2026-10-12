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
The workflow's manual run verifies token exchange without uploading
a new version. First-time publication of a new package still requires an owner
to bootstrap it and register its trusted publisher on crates.io.

## Dependency updates

All seven CI checks and CLA are required for `main`. Trusted default-branch
automation merges repository-local Dependabot PRs after mandatory CI and a
fresh positive review, with no unresolved threads or active changes requested.
Codex's positive verdict must follow the current head's recorded push; a trusted
collaborator approval must identify that exact commit. Missing review evidence
keeps the PR waiting. The merge operation also binds the inspected SHA.

`hashbrown` and `allocator-api2` changes require manual contract review, including
grouped updates and manifest/lockfile changes. Their audited capacity/layout
contracts cannot be qualified by CI alone. Other updates are checked on PR/CI
events, with an hourly backstop for verdict reactions that emit no Actions event.
The merge App token is scoped to this repository and created only when a
qualified update is ready; the automation never executes PR code with it.

## Development

Run `cargo nextest run --workspace`, `cargo test --workspace --doc`, and
`cargo clippy --workspace --all-targets -- -D warnings`.
Check alloc-only builds using `cargo check --workspace --no-default-features`
and the `wasm32-unknown-unknown` and `thumbv7em-none-eabihf` targets.
Verify distributable archives with `bash scripts/check-packages.sh`; it uses
fresh temporary package state so earlier same-version workspace archives cannot
substitute stale source during verification.
Release-trigger regressions use GitHub's expression evaluator: run
`npm ci --prefix .github/tests --ignore-scripts` followed by
`npm run check --prefix .github/tests`. CI runs the same checks before a main
commit can approve publication, including manual/fork refusals and preservation
of separate main-push validation runs.

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
