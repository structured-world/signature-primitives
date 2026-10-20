# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.2](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.9.1...structured-xades-v0.9.2) - 2026-10-20

### Added

- *(pkix)* decode DSA public key structure ([#155](https://github.com/structured-world/signature-primitives/pull/155))
- *(pkix)* decode DSS signature values ([#152](https://github.com/structured-world/signature-primitives/pull/152))

## [0.9.1](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.9.0...structured-xades-v0.9.1) - 2026-10-20

### Added

- *(pkix)* resolve SHA3 digest identifiers ([#149](https://github.com/structured-world/signature-primitives/pull/149))

## [0.9.0](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.8.1...structured-xades-v0.9.0) - 2026-10-20

### Added

- *(pkix)* [**breaking**] read revocation retention and not-issued status ([#147](https://github.com/structured-world/signature-primitives/pull/147))
- *(cms)* add CAdES archive-time-stamp-v3 coverage ([#146](https://github.com/structured-world/signature-primitives/pull/146))

### Other

- describe structured-ltv and the 0.8 API family ([#143](https://github.com/structured-world/signature-primitives/pull/143))

## [0.8.1](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.8.0...structured-xades-v0.8.1) - 2026-10-19

### Added

- *(asn1)* expose remaining work through Work ([#141](https://github.com/structured-world/signature-primitives/pull/141))

## [0.8.0](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.7.0...structured-xades-v0.8.0) - 2026-10-19

### Added

- *(ltv)* [**breaking**] move format-neutral long-term validation into structured-ltv ([#136](https://github.com/structured-world/signature-primitives/pull/136))

### Other

- *(pkix)* measure SAN lookup work independently of the seed ([#138](https://github.com/structured-world/signature-primitives/pull/138))

## [0.7.0](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.6.3...structured-xades-v0.7.0) - 2026-10-18

### Added

- [**breaking**] share one incremental digest contract ([#131](https://github.com/structured-world/signature-primitives/pull/131))
- *(xades)* assess baseline levels and qualify against independent fixtures ([#129](https://github.com/structured-world/signature-primitives/pull/129))

## [0.6.3](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.6.2...structured-xades-v0.6.3) - 2026-10-18

### Added

- *(pkix)* read RSA and EC public keys structurally ([#125](https://github.com/structured-world/signature-primitives/pull/125))

### Other

- qualify published crates from the registry ([#122](https://github.com/structured-world/signature-primitives/pull/122))

## [0.6.2](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.6.1...structured-xades-v0.6.2) - 2026-10-17

### Added

- *(asn1)* finish and rebind OwnedMap without copying ([#118](https://github.com/structured-world/signature-primitives/pull/118))

## [0.6.1](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.6.0...structured-xades-v0.6.1) - 2026-10-17

### Added

- *(pkix)* extract borrowed PSS parameters ([#115](https://github.com/structured-world/signature-primitives/pull/115))

## [0.6.0](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.5.0...structured-xades-v0.6.0) - 2026-10-17

### Fixed

- *(cms)* [**breaking**] retain attribute inspection faults ([#110](https://github.com/structured-world/signature-primitives/pull/110))

## [0.5.0](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.4.5...structured-xades-v0.5.0) - 2026-10-17

### Fixed

- *(cms)* [**breaking**] retain malformed signer algorithms ([#103](https://github.com/structured-world/signature-primitives/pull/103))
- *(pkix)* scope attribute folding work ([#105](https://github.com/structured-world/signature-primitives/pull/105))
- *(cms)* retain empty attribute inspection ([#108](https://github.com/structured-world/signature-primitives/pull/108))

## [0.4.5](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.4.4...structured-xades-v0.4.5) - 2026-10-16

### Added

- *(memory)* mutate maps with borrowed queries ([#99](https://github.com/structured-world/signature-primitives/pull/99))

## [0.4.4](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.4.3...structured-xades-v0.4.4) - 2026-10-16

### Added

- *(memory)* reserve validated text capacity ([#97](https://github.com/structured-world/signature-primitives/pull/97))
- *(memory)* drain reusable accounted buffers ([#94](https://github.com/structured-world/signature-primitives/pull/94))
- *(memory)* append validated UTF-8 text ([#92](https://github.com/structured-world/signature-primitives/pull/92))

## [0.4.3](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.4.2...structured-xades-v0.4.3) - 2026-10-16

### Added

- *(memory)* add immutable owned text ([#89](https://github.com/structured-world/signature-primitives/pull/89))

## [0.4.2](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.4.1...structured-xades-v0.4.2) - 2026-10-16

### Added

- *(memory)* add borrowed map lookup ([#86](https://github.com/structured-world/signature-primitives/pull/86))
- *(memory)* add shared immutable strings ([#84](https://github.com/structured-world/signature-primitives/pull/84))

## [0.4.1](https://github.com/structured-world/signature-primitives/compare/structured-xades-v0.4.0...structured-xades-v0.4.1) - 2026-10-16

### Added

- *(memory)* add fallible map filtering ([#79](https://github.com/structured-world/signature-primitives/pull/79))
