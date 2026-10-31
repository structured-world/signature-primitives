# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
