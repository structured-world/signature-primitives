# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.16.1](https://github.com/structured-world/signature-primitives/compare/v0.16.0...v0.16.1) - 2026-10-27

### Added

- *(pkix)* expose signature profile inspection ([#241](https://github.com/structured-world/signature-primitives/pull/241))

## [0.16.0](https://github.com/structured-world/signature-primitives/compare/v0.15.2...v0.16.0) - 2026-10-27

### Other

- *(cms)* [**breaking**] transfer decrypted key ownership ([#236](https://github.com/structured-world/signature-primitives/pull/236))

## [0.15.2](https://github.com/structured-world/signature-primitives/compare/v0.15.1...v0.15.2) - 2026-10-26

### Added

- *(pkix)* verify alternative X.509 signatures ([#234](https://github.com/structured-world/signature-primitives/pull/234))

### Other

- *(deps)* bump structured-email-address from 0.0.21 to 0.0.22 ([#231](https://github.com/structured-world/signature-primitives/pull/231))

## [0.15.1](https://github.com/structured-world/signature-primitives/compare/v0.15.0...v0.15.1) - 2026-10-24

### Other

- *(release)* enable trusted container releases ([#226](https://github.com/structured-world/signature-primitives/pull/226))

## [0.15.0](https://github.com/structured-world/signature-primitives/compare/v0.14.0...v0.15.0) - 2026-10-24

### Added

- *(asic)* [**breaking**] add source-bound ASiC validation ([#223](https://github.com/structured-world/signature-primitives/pull/223))

## [0.14.0](https://github.com/structured-world/signature-primitives/compare/v0.13.0...v0.14.0) - 2026-10-24

### Added

- *(pades)* [**breaking**] add PDF signature baselines ([#220](https://github.com/structured-world/signature-primitives/pull/220))

## [0.13.0](https://github.com/structured-world/signature-primitives/compare/v0.12.0...v0.13.0) - 2026-10-23

### Added

- *(cms)* [**breaking**] verify ers and cades preservation ([#216](https://github.com/structured-world/signature-primitives/pull/216))

## [0.12.0](https://github.com/structured-world/signature-primitives/compare/v0.11.0...v0.12.0) - 2026-10-22

### Added

- *(cades)* verify reference timestamps ([#213](https://github.com/structured-world/signature-primitives/pull/213))
- *(cades)* [**breaking**] verify historical archives ([#211](https://github.com/structured-world/signature-primitives/pull/211))
- *(cades)* compose baseline levels ([#174](https://github.com/structured-world/signature-primitives/pull/174))

### Other

- release v0.11.0 ([#192](https://github.com/structured-world/signature-primitives/pull/192))
- release v0.10.0 ([#158](https://github.com/structured-world/signature-primitives/pull/158))

## [0.11.0](https://github.com/structured-world/signature-primitives/compare/v0.10.0...v0.11.0) - 2026-10-22

### Added

- *(cades)* [**breaking**] verify historical archives ([#211](https://github.com/structured-world/signature-primitives/pull/211))
- *(cms)* process protected key containers ([#209](https://github.com/structured-world/signature-primitives/pull/209))
- *(tsp)* check complete timestamp responses ([#205](https://github.com/structured-world/signature-primitives/pull/205))
- *(cms)* process encrypted AC attributes ([#203](https://github.com/structured-world/signature-primitives/pull/203))
- *(cms)* validate attribute-certificate use ([#201](https://github.com/structured-world/signature-primitives/pull/201))
- *(cms)* authenticate constrained AA paths ([#199](https://github.com/structured-world/signature-primitives/pull/199))
- *(ocsp)* [**breaking**] support attribute certificate status ([#197](https://github.com/structured-world/signature-primitives/pull/197))
- *(pkix)* [**breaking**] support AC CRL evidence ([#195](https://github.com/structured-world/signature-primitives/pull/195))
- *(cms)* authenticate attribute certificates ([#193](https://github.com/structured-world/signature-primitives/pull/193))
- *(cms)* bind holder object digests ([#190](https://github.com/structured-world/signature-primitives/pull/190))
- *(ocsp)* process original request batches ([#207](https://github.com/structured-world/signature-primitives/pull/207))

## [0.10.0](https://github.com/structured-world/signature-primitives/compare/v0.9.2...v0.10.0) - 2026-10-21

### Added

- *(cms)* check attribute certificate inputs ([#188](https://github.com/structured-world/signature-primitives/pull/188))
- *(cms)* complete ac clearance and controls ([#186](https://github.com/structured-world/signature-primitives/pull/186))
- *(cms)* read service and access identities ([#184](https://github.com/structured-world/signature-primitives/pull/184))
- *(cms)* decode original AC role assertions ([#182](https://github.com/structured-world/signature-primitives/pull/182))
- *(cms)* read IETF AC attribute values ([#180](https://github.com/structured-world/signature-primitives/pull/180))
- *(cms)* check AC recipient targeting ([#178](https://github.com/structured-world/signature-primitives/pull/178))
- *(cms)* read v2 attribute certificates ([#176](https://github.com/structured-world/signature-primitives/pull/176))
- *(cades)* compose baseline levels ([#174](https://github.com/structured-world/signature-primitives/pull/174))
- *(pkix)* read RFC 8410 public key structure ([#157](https://github.com/structured-world/signature-primitives/pull/157))
- *(pkix)* share ml-dsa public structure ([#172](https://github.com/structured-world/signature-primitives/pull/172))
- *(pkix)* interpret PSS key restrictions ([#168](https://github.com/structured-world/signature-primitives/pull/168))
- *(pkix)* read signature algorithm structure ([#166](https://github.com/structured-world/signature-primitives/pull/166))
- *(pkix)* read retained PSS parameters ([#162](https://github.com/structured-world/signature-primitives/pull/162))
- *(pkix)* [**breaking**] retain signature source context ([#160](https://github.com/structured-world/signature-primitives/pull/160))

### Fixed

- *(pkix)* preserve digest source work limits ([#164](https://github.com/structured-world/signature-primitives/pull/164))
- *(pkix)* preserve key source work limits ([#170](https://github.com/structured-world/signature-primitives/pull/170))

## [0.9.2](https://github.com/structured-world/signature-primitives/compare/v0.9.1...v0.9.2) - 2026-10-20

### Added

- *(pkix)* decode DSS signature values ([#152](https://github.com/structured-world/signature-primitives/pull/152))
- *(pkix)* decode DSA public key structure ([#155](https://github.com/structured-world/signature-primitives/pull/155))

## [0.9.1](https://github.com/structured-world/signature-primitives/compare/v0.9.0...v0.9.1) - 2026-10-20

### Added

- *(pkix)* resolve SHA3 digest identifiers ([#149](https://github.com/structured-world/signature-primitives/pull/149))

## [0.9.0](https://github.com/structured-world/signature-primitives/compare/v0.8.1...v0.9.0) - 2026-10-20

### Added

- *(cms)* add CAdES archive-time-stamp-v3 coverage ([#146](https://github.com/structured-world/signature-primitives/pull/146))
- *(pkix)* [**breaking**] read revocation retention and not-issued status ([#147](https://github.com/structured-world/signature-primitives/pull/147))

### Other

- describe structured-ltv and the 0.8 API family ([#143](https://github.com/structured-world/signature-primitives/pull/143))

## [0.8.1](https://github.com/structured-world/signature-primitives/compare/v0.8.0...v0.8.1) - 2026-10-19

### Added

- *(asn1)* expose remaining work through Work ([#141](https://github.com/structured-world/signature-primitives/pull/141))

## [0.8.0](https://github.com/structured-world/signature-primitives/compare/v0.7.0...v0.8.0) - 2026-10-19

### Added

- *(ltv)* [**breaking**] move format-neutral long-term validation into structured-ltv ([#136](https://github.com/structured-world/signature-primitives/pull/136))

### Other

- *(pkix)* measure SAN lookup work independently of the seed ([#138](https://github.com/structured-world/signature-primitives/pull/138))

## [0.7.0](https://github.com/structured-world/signature-primitives/compare/v0.6.3...v0.7.0) - 2026-10-18

### Added

- [**breaking**] share one incremental digest contract ([#131](https://github.com/structured-world/signature-primitives/pull/131))
- *(xades)* assess baseline levels and qualify against independent fixtures ([#129](https://github.com/structured-world/signature-primitives/pull/129))

## [0.6.3](https://github.com/structured-world/signature-primitives/compare/v0.6.2...v0.6.3) - 2026-10-18

### Added

- *(pkix)* read RSA and EC public keys structurally ([#125](https://github.com/structured-world/signature-primitives/pull/125))

### Other

- qualify published crates from the registry ([#122](https://github.com/structured-world/signature-primitives/pull/122))

## [0.6.2](https://github.com/structured-world/signature-primitives/compare/v0.6.1...v0.6.2) - 2026-10-17

### Added

- *(asn1)* finish and rebind OwnedMap without copying ([#118](https://github.com/structured-world/signature-primitives/pull/118))

## [0.6.1](https://github.com/structured-world/signature-primitives/compare/v0.6.0...v0.6.1) - 2026-10-17

### Added

- *(pkix)* extract borrowed PSS parameters ([#115](https://github.com/structured-world/signature-primitives/pull/115))

## [0.6.0](https://github.com/structured-world/signature-primitives/compare/v0.5.0...v0.6.0) - 2026-10-17

### Fixed

- *(cms)* [**breaking**] retain attribute inspection faults ([#110](https://github.com/structured-world/signature-primitives/pull/110))

## [0.5.0](https://github.com/structured-world/signature-primitives/compare/v0.4.5...v0.5.0) - 2026-10-17

### Fixed

- *(cms)* retain empty attribute inspection ([#108](https://github.com/structured-world/signature-primitives/pull/108))
- *(cms)* [**breaking**] retain malformed signer algorithms ([#103](https://github.com/structured-world/signature-primitives/pull/103))
- *(pkix)* scope attribute folding work ([#105](https://github.com/structured-world/signature-primitives/pull/105))

## [0.4.5](https://github.com/structured-world/signature-primitives/compare/v0.4.4...v0.4.5) - 2026-10-16

### Added

- *(memory)* mutate maps with borrowed queries ([#99](https://github.com/structured-world/signature-primitives/pull/99))

## [0.4.4](https://github.com/structured-world/signature-primitives/compare/v0.4.3...v0.4.4) - 2026-10-16

### Added

- *(memory)* reserve validated text capacity ([#97](https://github.com/structured-world/signature-primitives/pull/97))
- *(memory)* drain reusable accounted buffers ([#94](https://github.com/structured-world/signature-primitives/pull/94))
- *(memory)* append validated UTF-8 text ([#92](https://github.com/structured-world/signature-primitives/pull/92))

## [0.4.3](https://github.com/structured-world/signature-primitives/compare/v0.4.2...v0.4.3) - 2026-10-16

### Added

- *(memory)* add immutable owned text ([#89](https://github.com/structured-world/signature-primitives/pull/89))

## [0.4.2](https://github.com/structured-world/signature-primitives/compare/v0.4.1...v0.4.2) - 2026-10-16

### Added

- *(memory)* add borrowed map lookup ([#86](https://github.com/structured-world/signature-primitives/pull/86))
- *(memory)* add shared immutable strings ([#84](https://github.com/structured-world/signature-primitives/pull/84))

## [0.4.1](https://github.com/structured-world/signature-primitives/compare/v0.4.0...v0.4.1) - 2026-10-16

### Added

- *(memory)* add fallible map filtering ([#79](https://github.com/structured-world/signature-primitives/pull/79))

## [0.4.0](https://github.com/structured-world/signature-primitives/compare/v0.3.0...v0.4.0) - 2026-10-16

### Added

- *(xades)* add baseline validation mechanisms ([#74](https://github.com/structured-world/signature-primitives/pull/74))

## [0.3.0](https://github.com/structured-world/signature-primitives/compare/v0.2.4...v0.3.0) - 2026-10-15

### Fixed

- *(pkix)* retain scoped execution and provenance ([#72](https://github.com/structured-world/signature-primitives/pull/72))

## [0.2.4](https://github.com/structured-world/signature-primitives/compare/v0.2.3...v0.2.4) - 2026-10-14

### Fixed

- *(tsp)* retain carried trailing-data faults ([#69](https://github.com/structured-world/signature-primitives/pull/69))

## [0.2.3](https://github.com/structured-world/signature-primitives/compare/v0.2.2...v0.2.3) - 2026-10-14

### Fixed

- *(tsp)* preserve unique recovery readings ([#66](https://github.com/structured-world/signature-primitives/pull/66))

## [0.2.2](https://github.com/structured-world/signature-primitives/compare/v0.2.1...v0.2.2) - 2026-10-14

### Fixed

- *(cms)* preserve duplicate timestamp identity ([#63](https://github.com/structured-world/signature-primitives/pull/63))

## [0.2.1](https://github.com/structured-world/signature-primitives/compare/v0.2.0...v0.2.1) - 2026-10-14

### Added

- *(pkix)* add algorithm inspection readings ([#60](https://github.com/structured-world/signature-primitives/pull/60))

## [0.2.0](https://github.com/structured-world/signature-primitives/compare/structured-cms-v0.1.6...structured-cms-v0.2.0) - 2026-10-14

### Added

- *(cms)* add bounded CMS and timestamp checks ([#47](https://github.com/structured-world/signature-primitives/pull/47))

### Fixed

- *(cms)* share duplicate digest identity ([#56](https://github.com/structured-world/signature-primitives/pull/56))

### Other

- document coordinated CMS consumption ([#54](https://github.com/structured-world/signature-primitives/pull/54))
