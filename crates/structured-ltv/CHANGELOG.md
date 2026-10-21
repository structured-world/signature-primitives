# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
