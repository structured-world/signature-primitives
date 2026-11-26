# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.30.1](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.30.0...structured-cades-v0.30.1) - 2026-11-26

### Added

- *(pkix)* share chain revocation effect ([#371](https://github.com/structured-world/signature-primitives/pull/371))

## [0.30.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.29.0...structured-cades-v0.30.0) - 2026-11-25

### Added

- [**breaking**] add prospective paths and delta CRL proofs ([#369](https://github.com/structured-world/signature-primitives/pull/369))

## [0.29.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.28.0...structured-cades-v0.29.0) - 2026-11-25

### Added

- *(xades)* expose pooled timestamp check facts ([#366](https://github.com/structured-world/signature-primitives/pull/366))

### Fixed

- *(xades)* [**breaking**] validate legacy certificate serials ([#365](https://github.com/structured-world/signature-primitives/pull/365))

### Other

- *(xades)* stabilize CRL catalogue work check ([#367](https://github.com/structured-world/signature-primitives/pull/367))

## [0.28.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.27.1...structured-cades-v0.28.0) - 2026-11-24

### Added

- *(pkix)* add chain validity model ([#364](https://github.com/structured-world/signature-primitives/pull/364))

### Other

- accelerate archive and path processing ([#362](https://github.com/structured-world/signature-primitives/pull/362))

## [0.27.1](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.27.0...structured-cades-v0.27.1) - 2026-11-24

### Added

- *(pkix)* share path signature answers ([#360](https://github.com/structured-world/signature-primitives/pull/360))
- *(xades)* admit legacy V1.2.2 properties ([#361](https://github.com/structured-world/signature-primitives/pull/361))

### Other

- reuse CRL metadata and singleton digests ([#353](https://github.com/structured-world/signature-primitives/pull/353))
- accelerate short PDF and ZIP comparisons ([#359](https://github.com/structured-world/signature-primitives/pull/359))
- *(pades)* reuse decoded VRI object streams ([#358](https://github.com/structured-world/signature-primitives/pull/358))
- *(asic)* scan ZIP end markers by word ([#356](https://github.com/structured-world/signature-primitives/pull/356))

## [0.27.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.26.0...structured-cades-v0.27.0) - 2026-11-24

### Fixed

- *(pkix)* [**breaking**] scope OCSP nonce binding failures ([#349](https://github.com/structured-world/signature-primitives/pull/349))

### Other

- *(cades)* merge archive ranges in wire order ([#355](https://github.com/structured-world/signature-primitives/pull/355))
- *(asn1)* reserve diagnostic paths once ([#350](https://github.com/structured-world/signature-primitives/pull/350))
- reuse signature validation inputs ([#346](https://github.com/structured-world/signature-primitives/pull/346))
- reduce XAdES and DSTU verification work ([#352](https://github.com/structured-world/signature-primitives/pull/352))
- *(pades)* compare original stream windows ([#351](https://github.com/structured-world/signature-primitives/pull/351))
- *(base64)* accelerate long AArch64 streams ([#354](https://github.com/structured-world/signature-primitives/pull/354))
- *(base64)* decode short MIME tails in quartets ([#347](https://github.com/structured-world/signature-primitives/pull/347))

## [0.26.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.25.1...structured-cades-v0.26.0) - 2026-11-24

### Fixed

- *(ltv)* [**breaking**] handle direct signer trust and CRLs ([#343](https://github.com/structured-world/signature-primitives/pull/343))

### Other

- remove repeated validation and decoding work ([#345](https://github.com/structured-world/signature-primitives/pull/345))

## [0.25.1](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.25.0...structured-cades-v0.25.1) - 2026-11-23

### Other

- *(base64)* reduce strict decode packing cost ([#340](https://github.com/structured-world/signature-primitives/pull/340))

## [0.25.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.24.0...structured-cades-v0.25.0) - 2026-11-23

### Added

- *(base64)* [**breaking**] add located decoding and faster strict profiles ([#338](https://github.com/structured-world/signature-primitives/pull/338))

## [0.24.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.23.2...structured-cades-v0.24.0) - 2026-11-23

### Added

- *(ltv)* assess supplied revocation evidence ([#336](https://github.com/structured-world/signature-primitives/pull/336))
- *(ltv)* validate signatures with archival proof ([#330](https://github.com/structured-world/signature-primitives/pull/330))
- *(ltv)* add ETSI validation process ([#328](https://github.com/structured-world/signature-primitives/pull/328))
- *(asic)* probe physical formats ([#334](https://github.com/structured-world/signature-primitives/pull/334))

### Fixed

- retain retry origin and enforce BER limits ([#332](https://github.com/structured-world/signature-primitives/pull/332))
- *(ltv)* [**breaking**] reconcile ETSI validation procedures ([#331](https://github.com/structured-world/signature-primitives/pull/331))

## [0.23.2](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.23.1...structured-cades-v0.23.2) - 2026-11-21

### Added

- *(pkix)* read X9.42 DH key containers ([#321](https://github.com/structured-world/signature-primitives/pull/321))

### Fixed

- *(pkix)* validate classical-only hybrid targets ([#323](https://github.com/structured-world/signature-primitives/pull/323))

## [0.23.1](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.23.0...structured-cades-v0.23.1) - 2026-11-15

### Fixed

- *(base64)* align streaming buffer boundaries ([#316](https://github.com/structured-world/signature-primitives/pull/316))

## [0.23.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.22.2...structured-cades-v0.23.0) - 2026-11-14

### Other

- *(hmac)* move implementation to foundation ([#313](https://github.com/structured-world/signature-primitives/pull/313))

## [0.22.2](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.22.1...structured-cades-v0.22.2) - 2026-11-14

### Added

- *(cms)* expose OpenSSL envelope KDF cost ([#311](https://github.com/structured-world/signature-primitives/pull/311))

## [0.22.1](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.22.0...structured-cades-v0.22.1) - 2026-11-14

### Added

- *(cms)* expose structural KDF costs ([#309](https://github.com/structured-world/signature-primitives/pull/309))

## [0.22.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.21.5...structured-cades-v0.22.0) - 2026-11-13

### Added

- *(cms)* open password-protected containers ([#308](https://github.com/structured-world/signature-primitives/pull/308))
- *(cms)* import traditional OpenSSL keys ([#307](https://github.com/structured-world/signature-primitives/pull/307))
- *(base64)* add strict JOSE profiles ([#304](https://github.com/structured-world/signature-primitives/pull/304))

### Other

- *(pkix)* [**breaking**] rename the effective path key ([#305](https://github.com/structured-world/signature-primitives/pull/305))

## [0.21.5](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.21.4...structured-cades-v0.21.5) - 2026-11-13

### Added

- *(cms)* add incremental HMAC ([#299](https://github.com/structured-world/signature-primitives/pull/299))

## [0.21.4](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.21.3...structured-cades-v0.21.4) - 2026-11-09

### Added

- *(base64)* add resumable codec ([#296](https://github.com/structured-world/signature-primitives/pull/296))

## [0.21.3](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.21.2...structured-cades-v0.21.3) - 2026-11-08

### Fixed

- *(asn1)* allow compatible resource dependencies ([#293](https://github.com/structured-world/signature-primitives/pull/293))

## [0.21.2](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.21.1...structured-cades-v0.21.2) - 2026-11-08

### Fixed

- *(deps)* allow compatible registry versions ([#291](https://github.com/structured-world/signature-primitives/pull/291))

### Other

- *(deps)* bump ml-dsa from 0.1.1 to 0.1.2 ([#286](https://github.com/structured-world/signature-primitives/pull/286))
- *(deps)* bump aes from 0.9.3 to 0.9.4 ([#287](https://github.com/structured-world/signature-primitives/pull/287))

## [0.21.1](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.21.0...structured-cades-v0.21.1) - 2026-11-07

### Fixed

- *(xades)* reuse pooled root timestamp tokens ([#282](https://github.com/structured-world/signature-primitives/pull/282))

## [0.21.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.20.3...structured-cades-v0.21.0) - 2026-11-06

### Fixed

- *(xades)* [**breaking**] construct new renewal methods ([#279](https://github.com/structured-world/signature-primitives/pull/279))

## [0.20.3](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.20.2...structured-cades-v0.20.3) - 2026-11-05

### Added

- *(xades)* add signature lifecycle construction ([#276](https://github.com/structured-world/signature-primitives/pull/276))

## [0.20.2](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.20.1...structured-cades-v0.20.2) - 2026-11-02

### Added

- *(hash)* add seeded table hashing ([#273](https://github.com/structured-world/signature-primitives/pull/273))

## [0.20.1](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.20.0...structured-cades-v0.20.1) - 2026-10-31

### Other

- streamline release and dependency workflows ([#269](https://github.com/structured-world/signature-primitives/pull/269))

## [0.20.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.19.0...structured-cades-v0.20.0) - 2026-10-31

### Added

- *(xades)* [**breaking**] separate token encoding profiles ([#266](https://github.com/structured-world/signature-primitives/pull/266))

## [0.19.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.18.2...structured-cades-v0.19.0) - 2026-10-31

### Added

- *(timestamp)* [**breaking**] accept TSA policy accuracy ([#263](https://github.com/structured-world/signature-primitives/pull/263))

## [0.18.2](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.18.1...structured-cades-v0.18.2) - 2026-10-31

### Added

- *(pkix)* compare bound delta CRL numbers ([#260](https://github.com/structured-world/signature-primitives/pull/260))

## [0.18.1](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.18.0...structured-cades-v0.18.1) - 2026-10-30

### Other

- *(release)* document published OIDC crates ([#257](https://github.com/structured-world/signature-primitives/pull/257))

## [0.18.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.17.1...structured-cades-v0.18.0) - 2026-10-30

### Added

- *(dstu4145)* add bounded Ukrainian verification ([#253](https://github.com/structured-world/signature-primitives/pull/253))
- *(pkix)* read dstu 4145 structures ([#250](https://github.com/structured-world/signature-primitives/pull/250))

### Other

- *(dstu4145)* optimize ONB and add RustCrypto traits ([#255](https://github.com/structured-world/signature-primitives/pull/255))

## [0.17.1](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.17.0...structured-cades-v0.17.1) - 2026-10-28

### Fixed

- expose core error traits without std ([#247](https://github.com/structured-world/signature-primitives/pull/247))

## [0.17.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.16.1...structured-cades-v0.17.0) - 2026-10-28

### Fixed

- *(pkix)* [**breaking**] retain EC parameter execution source ([#244](https://github.com/structured-world/signature-primitives/pull/244))

## [0.16.1](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.16.0...structured-cades-v0.16.1) - 2026-10-27

### Added

- *(pkix)* expose signature profile inspection ([#241](https://github.com/structured-world/signature-primitives/pull/241))

## [0.16.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.15.2...structured-cades-v0.16.0) - 2026-10-27

### Other

- *(cms)* [**breaking**] transfer decrypted key ownership ([#236](https://github.com/structured-world/signature-primitives/pull/236))

## [0.15.2](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.15.1...structured-cades-v0.15.2) - 2026-10-26

### Added

- *(pkix)* verify alternative X.509 signatures ([#234](https://github.com/structured-world/signature-primitives/pull/234))

### Other

- *(deps)* bump structured-email-address from 0.0.21 to 0.0.22 ([#231](https://github.com/structured-world/signature-primitives/pull/231))

## [0.15.1](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.15.0...structured-cades-v0.15.1) - 2026-10-24

### Other

- *(release)* enable trusted container releases ([#226](https://github.com/structured-world/signature-primitives/pull/226))

## [0.15.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.14.0...structured-cades-v0.15.0) - 2026-10-24

### Added

- *(asic)* [**breaking**] add source-bound ASiC validation ([#223](https://github.com/structured-world/signature-primitives/pull/223))

## [0.14.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.13.0...structured-cades-v0.14.0) - 2026-10-24

### Added

- *(pades)* [**breaking**] add PDF signature baselines ([#220](https://github.com/structured-world/signature-primitives/pull/220))

## [0.13.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.12.0...structured-cades-v0.13.0) - 2026-10-23

### Added

- *(cms)* [**breaking**] verify ers and cades preservation ([#216](https://github.com/structured-world/signature-primitives/pull/216))

## [0.12.0](https://github.com/structured-world/signature-primitives/compare/structured-cades-v0.11.0...structured-cades-v0.12.0) - 2026-10-22

### Added

- *(cades)* verify reference timestamps ([#213](https://github.com/structured-world/signature-primitives/pull/213))
- *(cades)* [**breaking**] verify historical archives ([#211](https://github.com/structured-world/signature-primitives/pull/211))
- *(cades)* compose baseline levels ([#174](https://github.com/structured-world/signature-primitives/pull/174))

### Other

- release v0.11.0 ([#192](https://github.com/structured-world/signature-primitives/pull/192))
- release v0.10.0 ([#158](https://github.com/structured-world/signature-primitives/pull/158))
