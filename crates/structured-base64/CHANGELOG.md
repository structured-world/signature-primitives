# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.31.0](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.30.4...structured-base64-v0.31.0) - 2026-11-26

### Added

- *(xades)* [**breaking**] support historical profiles ([#383](https://github.com/structured-world/signature-primitives/pull/383))

## [0.30.4](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.30.3...structured-base64-v0.30.4) - 2026-11-26

### Added

- *(xades)* support extended signatures ([#380](https://github.com/structured-world/signature-primitives/pull/380))

## [0.30.3](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.30.2...structured-base64-v0.30.3) - 2026-11-26

### Added

- *(policy)* support supplied and DER digests ([#377](https://github.com/structured-world/signature-primitives/pull/377))

## [0.30.2](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.30.1...structured-base64-v0.30.2) - 2026-11-26

### Added

- *(xades)* produce qualifying properties ([#374](https://github.com/structured-world/signature-primitives/pull/374))

## [0.30.1](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.30.0...structured-base64-v0.30.1) - 2026-11-26

### Added

- *(pkix)* share chain revocation effect ([#371](https://github.com/structured-world/signature-primitives/pull/371))

## [0.30.0](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.29.0...structured-base64-v0.30.0) - 2026-11-25

### Added

- [**breaking**] add prospective paths and delta CRL proofs ([#369](https://github.com/structured-world/signature-primitives/pull/369))

## [0.29.0](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.28.0...structured-base64-v0.29.0) - 2026-11-25

### Added

- *(xades)* expose pooled timestamp check facts ([#366](https://github.com/structured-world/signature-primitives/pull/366))

### Fixed

- *(xades)* [**breaking**] validate legacy certificate serials ([#365](https://github.com/structured-world/signature-primitives/pull/365))

### Other

- *(xades)* stabilize CRL catalogue work check ([#367](https://github.com/structured-world/signature-primitives/pull/367))

## [0.28.0](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.27.1...structured-base64-v0.28.0) - 2026-11-24

### Added

- *(pkix)* add chain validity model ([#364](https://github.com/structured-world/signature-primitives/pull/364))

### Other

- accelerate archive and path processing ([#362](https://github.com/structured-world/signature-primitives/pull/362))

## [0.27.1](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.27.0...structured-base64-v0.27.1) - 2026-11-24

### Added

- *(pkix)* share path signature answers ([#360](https://github.com/structured-world/signature-primitives/pull/360))
- *(xades)* admit legacy V1.2.2 properties ([#361](https://github.com/structured-world/signature-primitives/pull/361))

### Other

- reuse CRL metadata and singleton digests ([#353](https://github.com/structured-world/signature-primitives/pull/353))
- accelerate short PDF and ZIP comparisons ([#359](https://github.com/structured-world/signature-primitives/pull/359))
- *(pades)* reuse decoded VRI object streams ([#358](https://github.com/structured-world/signature-primitives/pull/358))
- *(asic)* scan ZIP end markers by word ([#356](https://github.com/structured-world/signature-primitives/pull/356))

## [0.27.0](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.26.0...structured-base64-v0.27.0) - 2026-11-24

### Fixed

- *(pkix)* [**breaking**] scope OCSP nonce binding failures ([#349](https://github.com/structured-world/signature-primitives/pull/349))

### Other

- *(base64)* accelerate long AArch64 streams ([#354](https://github.com/structured-world/signature-primitives/pull/354))
- *(base64)* decode short MIME tails in quartets ([#347](https://github.com/structured-world/signature-primitives/pull/347))
- reuse signature validation inputs ([#346](https://github.com/structured-world/signature-primitives/pull/346))
- *(asn1)* reserve diagnostic paths once ([#350](https://github.com/structured-world/signature-primitives/pull/350))
- reduce XAdES and DSTU verification work ([#352](https://github.com/structured-world/signature-primitives/pull/352))
- *(cades)* merge archive ranges in wire order ([#355](https://github.com/structured-world/signature-primitives/pull/355))
- *(pades)* compare original stream windows ([#351](https://github.com/structured-world/signature-primitives/pull/351))

## [0.26.0](https://github.com/structured-world/signature-primitives/compare/structured-base64-v0.25.1...structured-base64-v0.26.0) - 2026-11-24

### Fixed

- *(ltv)* [**breaking**] handle direct signer trust and CRLs ([#343](https://github.com/structured-world/signature-primitives/pull/343))

### Other

- remove repeated validation and decoding work ([#345](https://github.com/structured-world/signature-primitives/pull/345))

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
