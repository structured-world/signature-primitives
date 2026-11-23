# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.25.1](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.25.0...structured-base64-v0.25.1) - 2026-11-23

### Other

- *(base64)* reduce strict decode packing cost ([#340](https://github.com/structured-world/signature-primitives/pull/340))

## [0.25.0](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.24.0...structured-base64-v0.25.0) - 2026-11-23

### Added

- *(base64)* [**breaking**] add located decoding and faster strict profiles ([#338](https://github.com/structured-world/signature-primitives/pull/338))

## [0.24.0](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.23.2...structured-base64-v0.24.0) - 2026-11-23

### Added

- *(ltv)* assess supplied revocation evidence ([#336](https://github.com/structured-world/signature-primitives/pull/336))
- *(ltv)* validate signatures with archival proof ([#330](https://github.com/structured-world/signature-primitives/pull/330))
- *(ltv)* add ETSI validation process ([#328](https://github.com/structured-world/signature-primitives/pull/328))
- *(asic)* probe physical formats ([#334](https://github.com/structured-world/signature-primitives/pull/334))

### Fixed

- retain retry origin and enforce BER limits ([#332](https://github.com/structured-world/signature-primitives/pull/332))
- *(ltv)* [**breaking**] reconcile ETSI validation procedures ([#331](https://github.com/structured-world/signature-primitives/pull/331))

## [0.23.2](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.23.1...structured-base64-v0.23.2) - 2026-11-21

### Added

- *(pkix)* read X9.42 DH key containers ([#321](https://github.com/structured-world/signature-primitives/pull/321))

### Fixed

- *(pkix)* validate classical-only hybrid targets ([#323](https://github.com/structured-world/signature-primitives/pull/323))

## [0.23.1](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.23.0...structured-base64-v0.23.1) - 2026-11-15

### Fixed

- *(base64)* align streaming buffer boundaries ([#316](https://github.com/structured-world/signature-primitives/pull/316))

## [0.23.0](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.22.2...structured-base64-v0.23.0) - 2026-11-14

### Other

- *(hmac)* move implementation to foundation ([#313](https://github.com/structured-world/signature-primitives/pull/313))

## [0.22.2](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.22.1...structured-base64-v0.22.2) - 2026-11-14

### Added

- *(cms)* expose OpenSSL envelope KDF cost ([#311](https://github.com/structured-world/signature-primitives/pull/311))

## [0.22.1](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.22.0...structured-base64-v0.22.1) - 2026-11-14

### Added

- *(cms)* expose structural KDF costs ([#309](https://github.com/structured-world/signature-primitives/pull/309))

## [0.22.0](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.21.5...structured-base64-v0.22.0) - 2026-11-13

### Added

- *(base64)* add strict JOSE profiles ([#304](https://github.com/structured-world/signature-primitives/pull/304))
- *(cms)* open password-protected containers ([#308](https://github.com/structured-world/signature-primitives/pull/308))
- *(cms)* import traditional OpenSSL keys ([#307](https://github.com/structured-world/signature-primitives/pull/307))

### Other

- *(pkix)* [**breaking**] rename the effective path key ([#305](https://github.com/structured-world/signature-primitives/pull/305))

## [0.21.5](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.21.4...structured-base64-v0.21.5) - 2026-11-13

### Added

- *(cms)* add incremental HMAC ([#299](https://github.com/structured-world/signature-primitives/pull/299))

## [0.21.4](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.21.3...structured-base64-v0.21.4) - 2026-11-09

### Added

- *(base64)* add resumable codec ([#296](https://github.com/structured-world/signature-primitives/pull/296))
