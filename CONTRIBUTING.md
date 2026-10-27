# Contributing

Open an issue describing the observable behavior and its governing specification.
Changes should include focused regression tests and preserve `no_std + alloc`.
Keep provider-specific crypto and application trust decisions outside format readers.

## Contributor License Agreement

Before a first pull request can be merged, you sign the Structured World
Contributor License Agreement once, at <https://sw.foundation/cla>. It covers
every repository of the organisation and takes a minute: sign in with GitHub,
confirm your e-mail address, sign. The `CLA` status on your pull request then
turns green by itself.

You keep the copyright in your contribution. If you contribute as part of your
job, your employer may also need to sign the corporate agreement; the page
above explains when.

## Development

Builds and CI use the latest stable Rust compiler through the unversioned
`stable` channel. Package `rust-version` metadata does not select a compiler.

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

## Releases

`structured-asn1`, `structured-pkix`, `structured-cms`, `structured-ltv` and
`structured-xades` use one release-plz version group.
Release-plz prepares a version/changelog PR using the organization release bot;
merging that PR publishes the packages after CI succeeds on its exact main commit.
Dependencies are published before their dependants. Git tags and release notes
retain each package's name, even though all five packages share their version.

Registry publishing uses OIDC, bound to this repository, `release-plz.yml` and
the `release` environment. Normal publication stores no long-lived crates.io
token in GitHub.
Manual runs enforce the same exact-SHA CI and release-PR gates; they do not
force an upload or prove token exchange when nothing requires publication.
First-time publication requires a limited API token because crates.io cannot
register an unpublished crate's trusted publisher. For the first LTV version,
the temporary repository Actions secret `LTV_BOOTSTRAP_TOKEN` selects three
steps: ASN.1, PKIX and CMS publish through OIDC, `structured-ltv` publishes with
that token, then `structured-xades`, which depends on it, publishes through
OIDC once Cargo resolves the new LTV version. Limit the token to `publish-new` for `structured-ltv`. After the first
publication, register the crate's Trusted Publisher with repository owner
`structured-world`, repository `signature-primitives`, workflow
`release-plz.yml` and environment `release`. Then delete the
`LTV_BOOTSTRAP_TOKEN` repository secret and revoke the temporary crates.io
token. Removing the secret selects normal OIDC for all five packages; leaving
it installed keeps the bootstrap path selected.

## Dependency updates

All seven CI checks and CLA are required for `main`. Trusted default-branch
automation qualifies repository-local Dependabot PRs by CI alone: a PR whose
required checks pass on a branch that is current with `main` is merged, and a
PR that is only behind `main` is updated so that CI runs again on the new head.
No review is required. Both operations bind the inspected head SHA, so a head
changed since inspection is refused and left for the next event.

`hashbrown` and `allocator-api2` changes require manual contract review, including
grouped updates and manifest/lockfile changes. Their audited capacity/layout
contracts cannot be qualified by CI alone. Other updates are checked when a
Dependabot PR is opened or updated and when CI completes, with an hourly
backstop for an event GitHub did not deliver.
The merge App token is scoped to this repository and created only when an
update or merge is due; the automation never executes PR code with it.
