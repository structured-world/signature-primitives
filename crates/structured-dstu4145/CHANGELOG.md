# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.27.1](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.27.0...structured-dstu4145-v0.27.1) - 2026-11-24

### Added

- *(pkix)* share path signature answers ([#360](https://github.com/structured-world/signature-primitives/pull/360))
- *(xades)* admit legacy V1.2.2 properties ([#361](https://github.com/structured-world/signature-primitives/pull/361))

### Other

- reuse CRL metadata and singleton digests ([#353](https://github.com/structured-world/signature-primitives/pull/353))
- accelerate short PDF and ZIP comparisons ([#359](https://github.com/structured-world/signature-primitives/pull/359))
- *(pades)* reuse decoded VRI object streams ([#358](https://github.com/structured-world/signature-primitives/pull/358))
- *(asic)* scan ZIP end markers by word ([#356](https://github.com/structured-world/signature-primitives/pull/356))

## [0.27.0](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.26.0...structured-dstu4145-v0.27.0) - 2026-11-24

### Fixed

- *(pkix)* [**breaking**] scope OCSP nonce binding failures ([#349](https://github.com/structured-world/signature-primitives/pull/349))

### Other

- reduce XAdES and DSTU verification work ([#352](https://github.com/structured-world/signature-primitives/pull/352))
- reuse signature validation inputs ([#346](https://github.com/structured-world/signature-primitives/pull/346))
- *(asn1)* reserve diagnostic paths once ([#350](https://github.com/structured-world/signature-primitives/pull/350))
- *(cades)* merge archive ranges in wire order ([#355](https://github.com/structured-world/signature-primitives/pull/355))
- *(pades)* compare original stream windows ([#351](https://github.com/structured-world/signature-primitives/pull/351))
- *(base64)* accelerate long AArch64 streams ([#354](https://github.com/structured-world/signature-primitives/pull/354))
- *(base64)* decode short MIME tails in quartets ([#347](https://github.com/structured-world/signature-primitives/pull/347))

## [0.26.0](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.25.1...structured-dstu4145-v0.26.0) - 2026-11-24

### Fixed

- *(ltv)* [**breaking**] handle direct signer trust and CRLs ([#343](https://github.com/structured-world/signature-primitives/pull/343))

### Other

- remove repeated validation and decoding work ([#345](https://github.com/structured-world/signature-primitives/pull/345))

## [0.25.1](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.25.0...structured-dstu4145-v0.25.1) - 2026-11-23

### Other

- *(base64)* reduce strict decode packing cost ([#340](https://github.com/structured-world/signature-primitives/pull/340))

## [0.25.0](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.24.0...structured-dstu4145-v0.25.0) - 2026-11-23

### Added

- *(base64)* [**breaking**] add located decoding and faster strict profiles ([#338](https://github.com/structured-world/signature-primitives/pull/338))

## [0.24.0](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.23.2...structured-dstu4145-v0.24.0) - 2026-11-23

### Added

- *(ltv)* assess supplied revocation evidence ([#336](https://github.com/structured-world/signature-primitives/pull/336))
- *(ltv)* validate signatures with archival proof ([#330](https://github.com/structured-world/signature-primitives/pull/330))
- *(ltv)* add ETSI validation process ([#328](https://github.com/structured-world/signature-primitives/pull/328))
- *(asic)* probe physical formats ([#334](https://github.com/structured-world/signature-primitives/pull/334))

### Fixed

- retain retry origin and enforce BER limits ([#332](https://github.com/structured-world/signature-primitives/pull/332))
- *(ltv)* [**breaking**] reconcile ETSI validation procedures ([#331](https://github.com/structured-world/signature-primitives/pull/331))

## [0.23.2](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.23.1...structured-dstu4145-v0.23.2) - 2026-11-21

### Added

- *(pkix)* read X9.42 DH key containers ([#321](https://github.com/structured-world/signature-primitives/pull/321))

### Fixed

- *(pkix)* validate classical-only hybrid targets ([#323](https://github.com/structured-world/signature-primitives/pull/323))

## [0.23.1](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.23.0...structured-dstu4145-v0.23.1) - 2026-11-15

### Fixed

- *(base64)* align streaming buffer boundaries ([#316](https://github.com/structured-world/signature-primitives/pull/316))

## [0.23.0](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.22.2...structured-dstu4145-v0.23.0) - 2026-11-14

### Other

- *(hmac)* move implementation to foundation ([#313](https://github.com/structured-world/signature-primitives/pull/313))

## [0.22.2](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.22.1...structured-dstu4145-v0.22.2) - 2026-11-14

### Added

- *(cms)* expose OpenSSL envelope KDF cost ([#311](https://github.com/structured-world/signature-primitives/pull/311))

## [0.22.1](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.22.0...structured-dstu4145-v0.22.1) - 2026-11-14

### Added

- *(cms)* expose structural KDF costs ([#309](https://github.com/structured-world/signature-primitives/pull/309))

## [0.22.0](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.21.5...structured-dstu4145-v0.22.0) - 2026-11-13

### Added

- *(cms)* open password-protected containers ([#308](https://github.com/structured-world/signature-primitives/pull/308))
- *(cms)* import traditional OpenSSL keys ([#307](https://github.com/structured-world/signature-primitives/pull/307))
- *(base64)* add strict JOSE profiles ([#304](https://github.com/structured-world/signature-primitives/pull/304))

### Other

- *(pkix)* [**breaking**] rename the effective path key ([#305](https://github.com/structured-world/signature-primitives/pull/305))

## [0.21.5](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.21.4...structured-dstu4145-v0.21.5) - 2026-11-13

### Added

- *(cms)* add incremental HMAC ([#299](https://github.com/structured-world/signature-primitives/pull/299))

## [0.21.4](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.21.3...structured-dstu4145-v0.21.4) - 2026-11-09

### Added

- *(base64)* add resumable codec ([#296](https://github.com/structured-world/signature-primitives/pull/296))

## [0.21.3](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.21.2...structured-dstu4145-v0.21.3) - 2026-11-08

### Fixed

- *(asn1)* allow compatible resource dependencies ([#293](https://github.com/structured-world/signature-primitives/pull/293))

## [0.21.2](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.21.1...structured-dstu4145-v0.21.2) - 2026-11-08

### Fixed

- *(deps)* allow compatible registry versions ([#291](https://github.com/structured-world/signature-primitives/pull/291))

### Other

- *(deps)* bump ml-dsa from 0.1.1 to 0.1.2 ([#286](https://github.com/structured-world/signature-primitives/pull/286))
- *(deps)* bump aes from 0.9.3 to 0.9.4 ([#287](https://github.com/structured-world/signature-primitives/pull/287))

## [0.21.1](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.21.0...structured-dstu4145-v0.21.1) - 2026-11-07

### Fixed

- *(xades)* reuse pooled root timestamp tokens ([#282](https://github.com/structured-world/signature-primitives/pull/282))

## [0.21.0](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.20.3...structured-dstu4145-v0.21.0) - 2026-11-06

### Fixed

- *(xades)* [**breaking**] construct new renewal methods ([#279](https://github.com/structured-world/signature-primitives/pull/279))

## [0.20.3](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.20.2...structured-dstu4145-v0.20.3) - 2026-11-05

### Added

- *(xades)* add signature lifecycle construction ([#276](https://github.com/structured-world/signature-primitives/pull/276))

## [0.20.2](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.20.1...structured-dstu4145-v0.20.2) - 2026-11-02

### Added

- *(hash)* add seeded table hashing ([#273](https://github.com/structured-world/signature-primitives/pull/273))

## [0.20.1](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.20.0...structured-dstu4145-v0.20.1) - 2026-10-31

### Other

- streamline release and dependency workflows ([#269](https://github.com/structured-world/signature-primitives/pull/269))

## [0.20.0](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.19.0...structured-dstu4145-v0.20.0) - 2026-10-31

### Added

- *(xades)* [**breaking**] separate token encoding profiles ([#266](https://github.com/structured-world/signature-primitives/pull/266))

## [0.19.0](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.18.2...structured-dstu4145-v0.19.0) - 2026-10-31

### Added

- *(timestamp)* [**breaking**] accept TSA policy accuracy ([#263](https://github.com/structured-world/signature-primitives/pull/263))

## [0.18.2](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.18.1...structured-dstu4145-v0.18.2) - 2026-10-31

### Added

- *(pkix)* compare bound delta CRL numbers ([#260](https://github.com/structured-world/signature-primitives/pull/260))

## [0.18.1](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.18.0...structured-dstu4145-v0.18.1) - 2026-10-30

### Other

- *(release)* document published OIDC crates ([#257](https://github.com/structured-world/signature-primitives/pull/257))

## [0.18.0](https://github.com/structured-world/signature-primitives/compare/structured-dstu4145-v0.17.1...structured-dstu4145-v0.18.0) - 2026-10-30

### Added

- *(dstu4145)* add bounded Ukrainian verification ([#253](https://github.com/structured-world/signature-primitives/pull/253))

### Other

- *(dstu4145)* optimize ONB and add RustCrypto traits ([#255](https://github.com/structured-world/signature-primitives/pull/255))
