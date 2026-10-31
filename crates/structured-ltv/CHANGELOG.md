# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.18.2](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.18.1...structured-ltv-v0.18.2) - 2026-10-31

### Added

- *(pkix)* compare bound delta CRL numbers ([#260](https://github.com/structured-world/signature-primitives/pull/260))

## [0.18.1](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.18.0...structured-ltv-v0.18.1) - 2026-10-30

### Other

- *(release)* document published OIDC crates ([#257](https://github.com/structured-world/signature-primitives/pull/257))

## [0.18.0](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.17.1...structured-ltv-v0.18.0) - 2026-10-30

### Added

- *(dstu4145)* add bounded Ukrainian verification ([#253](https://github.com/structured-world/signature-primitives/pull/253))
- *(pkix)* read dstu 4145 structures ([#250](https://github.com/structured-world/signature-primitives/pull/250))

### Other

- *(dstu4145)* optimize ONB and add RustCrypto traits ([#255](https://github.com/structured-world/signature-primitives/pull/255))

## [0.17.1](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.17.0...structured-ltv-v0.17.1) - 2026-10-28

### Fixed

- expose core error traits without std ([#247](https://github.com/structured-world/signature-primitives/pull/247))

## [0.17.0](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.16.1...structured-ltv-v0.17.0) - 2026-10-28

### Fixed

- *(pkix)* [**breaking**] retain EC parameter execution source ([#244](https://github.com/structured-world/signature-primitives/pull/244))

## [0.16.1](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.16.0...structured-ltv-v0.16.1) - 2026-10-27

### Added

- *(pkix)* expose signature profile inspection ([#241](https://github.com/structured-world/signature-primitives/pull/241))

## [0.16.0](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.15.2...structured-ltv-v0.16.0) - 2026-10-27

### Other

- *(cms)* [**breaking**] transfer decrypted key ownership ([#236](https://github.com/structured-world/signature-primitives/pull/236))

## [0.15.2](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.15.1...structured-ltv-v0.15.2) - 2026-10-26

### Added

- *(pkix)* verify alternative X.509 signatures ([#234](https://github.com/structured-world/signature-primitives/pull/234))

### Other

- *(deps)* bump structured-email-address from 0.0.21 to 0.0.22 ([#231](https://github.com/structured-world/signature-primitives/pull/231))

## [0.15.1](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.15.0...structured-ltv-v0.15.1) - 2026-10-24

### Other

- *(release)* enable trusted container releases ([#226](https://github.com/structured-world/signature-primitives/pull/226))

## [0.15.0](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.14.0...structured-ltv-v0.15.0) - 2026-10-24

### Added

- *(asic)* [**breaking**] add source-bound ASiC validation ([#223](https://github.com/structured-world/signature-primitives/pull/223))

## [0.14.0](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.13.0...structured-ltv-v0.14.0) - 2026-10-24

### Added

- *(pades)* [**breaking**] add PDF signature baselines ([#220](https://github.com/structured-world/signature-primitives/pull/220))

## [0.13.0](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.12.0...structured-ltv-v0.13.0) - 2026-10-23

### Added

- *(cms)* [**breaking**] verify ers and cades preservation ([#216](https://github.com/structured-world/signature-primitives/pull/216))

## [0.12.0](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.11.0...structured-ltv-v0.12.0) - 2026-10-22

### Added

- *(cades)* verify reference timestamps ([#213](https://github.com/structured-world/signature-primitives/pull/213))
- *(cades)* [**breaking**] verify historical archives ([#211](https://github.com/structured-world/signature-primitives/pull/211))
- *(cades)* compose baseline levels ([#174](https://github.com/structured-world/signature-primitives/pull/174))

### Other

- release v0.11.0 ([#192](https://github.com/structured-world/signature-primitives/pull/192))
- release v0.10.0 ([#158](https://github.com/structured-world/signature-primitives/pull/158))

## [0.11.0](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.10.0...structured-ltv-v0.11.0) - 2026-10-22

### Added

- *(cades)* [**breaking**] verify historical archives ([#211](https://github.com/structured-world/signature-primitives/pull/211))
- *(cms)* process protected key containers ([#209](https://github.com/structured-world/signature-primitives/pull/209))
- *(ocsp)* process original request batches ([#207](https://github.com/structured-world/signature-primitives/pull/207))
- *(cms)* validate attribute-certificate use ([#201](https://github.com/structured-world/signature-primitives/pull/201))
- *(cms)* authenticate constrained AA paths ([#199](https://github.com/structured-world/signature-primitives/pull/199))
- *(ocsp)* [**breaking**] support attribute certificate status ([#197](https://github.com/structured-world/signature-primitives/pull/197))
- *(pkix)* [**breaking**] support AC CRL evidence ([#195](https://github.com/structured-world/signature-primitives/pull/195))
- *(cms)* authenticate attribute certificates ([#193](https://github.com/structured-world/signature-primitives/pull/193))
- *(cms)* bind holder object digests ([#190](https://github.com/structured-world/signature-primitives/pull/190))
- *(tsp)* check complete timestamp responses ([#205](https://github.com/structured-world/signature-primitives/pull/205))
- *(cms)* process encrypted AC attributes ([#203](https://github.com/structured-world/signature-primitives/pull/203))

## [0.10.0](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.9.2...structured-ltv-v0.10.0) - 2026-10-21

### Added

- *(cades)* compose baseline levels ([#174](https://github.com/structured-world/signature-primitives/pull/174))
- *(pkix)* [**breaking**] retain signature source context ([#160](https://github.com/structured-world/signature-primitives/pull/160))
- *(pkix)* read RFC 8410 public key structure ([#157](https://github.com/structured-world/signature-primitives/pull/157))
- *(cms)* check attribute certificate inputs ([#188](https://github.com/structured-world/signature-primitives/pull/188))
- *(cms)* check AC recipient targeting ([#178](https://github.com/structured-world/signature-primitives/pull/178))
- *(cms)* read v2 attribute certificates ([#176](https://github.com/structured-world/signature-primitives/pull/176))
- *(pkix)* share ml-dsa public structure ([#172](https://github.com/structured-world/signature-primitives/pull/172))
- *(pkix)* interpret PSS key restrictions ([#168](https://github.com/structured-world/signature-primitives/pull/168))
- *(pkix)* read signature algorithm structure ([#166](https://github.com/structured-world/signature-primitives/pull/166))
- *(pkix)* read retained PSS parameters ([#162](https://github.com/structured-world/signature-primitives/pull/162))
- *(cms)* complete ac clearance and controls ([#186](https://github.com/structured-world/signature-primitives/pull/186))
- *(cms)* read service and access identities ([#184](https://github.com/structured-world/signature-primitives/pull/184))
- *(cms)* decode original AC role assertions ([#182](https://github.com/structured-world/signature-primitives/pull/182))
- *(cms)* read IETF AC attribute values ([#180](https://github.com/structured-world/signature-primitives/pull/180))

### Fixed

- *(pkix)* preserve key source work limits ([#170](https://github.com/structured-world/signature-primitives/pull/170))
- *(pkix)* preserve digest source work limits ([#164](https://github.com/structured-world/signature-primitives/pull/164))

## [0.9.2](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.9.1...structured-ltv-v0.9.2) - 2026-10-20

### Added

- *(pkix)* decode DSA public key structure ([#155](https://github.com/structured-world/signature-primitives/pull/155))
- *(pkix)* decode DSS signature values ([#152](https://github.com/structured-world/signature-primitives/pull/152))

## [0.9.1](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.9.0...structured-ltv-v0.9.1) - 2026-10-20

### Added

- *(pkix)* resolve SHA3 digest identifiers ([#149](https://github.com/structured-world/signature-primitives/pull/149))

## [0.9.0](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.8.1...structured-ltv-v0.9.0) - 2026-10-20

### Added

- *(cms)* add CAdES archive-time-stamp-v3 coverage ([#146](https://github.com/structured-world/signature-primitives/pull/146))
- *(pkix)* [**breaking**] read revocation retention and not-issued status ([#147](https://github.com/structured-world/signature-primitives/pull/147))

### Other

- describe structured-ltv and the 0.8 API family ([#143](https://github.com/structured-world/signature-primitives/pull/143))

## [0.8.1](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.8.0...structured-ltv-v0.8.1) - 2026-10-19

### Added

- *(asn1)* expose remaining work through Work ([#141](https://github.com/structured-world/signature-primitives/pull/141))

## [0.8.0](https://github.com/structured-world/signature-primitives/compare/structured-ltv-v0.7.0...structured-ltv-v0.8.0) - 2026-10-19

### Added

- *(ltv)* [**breaking**] move format-neutral long-term validation into structured-ltv ([#136](https://github.com/structured-world/signature-primitives/pull/136))
