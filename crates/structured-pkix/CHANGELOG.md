# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.3](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.6.2...structured-pkix-v0.6.3) - 2026-10-18

### Added

- *(pkix)* read RSA and EC public keys structurally ([#125](https://github.com/structured-world/signature-primitives/pull/125))

### Other

- qualify published crates from the registry ([#122](https://github.com/structured-world/signature-primitives/pull/122))

## [0.6.2](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.6.1...structured-pkix-v0.6.2) - 2026-10-17

### Added

- *(asn1)* finish and rebind OwnedMap without copying ([#118](https://github.com/structured-world/signature-primitives/pull/118))

## [0.6.1](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.6.0...structured-pkix-v0.6.1) - 2026-10-17

### Added

- *(pkix)* extract borrowed PSS parameters ([#115](https://github.com/structured-world/signature-primitives/pull/115))

## [0.6.0](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.5.0...structured-pkix-v0.6.0) - 2026-10-17

### Fixed

- *(cms)* [**breaking**] retain attribute inspection faults ([#110](https://github.com/structured-world/signature-primitives/pull/110))

## [0.5.0](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.4.5...structured-pkix-v0.5.0) - 2026-10-17

### Fixed

- *(pkix)* scope attribute folding work ([#105](https://github.com/structured-world/signature-primitives/pull/105))
- *(cms)* [**breaking**] retain malformed signer algorithms ([#103](https://github.com/structured-world/signature-primitives/pull/103))
- *(cms)* retain empty attribute inspection ([#108](https://github.com/structured-world/signature-primitives/pull/108))

## [0.4.5](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.4.4...structured-pkix-v0.4.5) - 2026-10-16

### Added

- *(memory)* mutate maps with borrowed queries ([#99](https://github.com/structured-world/signature-primitives/pull/99))

## [0.4.4](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.4.3...structured-pkix-v0.4.4) - 2026-10-16

### Added

- *(memory)* reserve validated text capacity ([#97](https://github.com/structured-world/signature-primitives/pull/97))
- *(memory)* drain reusable accounted buffers ([#94](https://github.com/structured-world/signature-primitives/pull/94))
- *(memory)* append validated UTF-8 text ([#92](https://github.com/structured-world/signature-primitives/pull/92))

## [0.4.3](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.4.2...structured-pkix-v0.4.3) - 2026-10-16

### Added

- *(memory)* add immutable owned text ([#89](https://github.com/structured-world/signature-primitives/pull/89))

## [0.4.2](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.4.1...structured-pkix-v0.4.2) - 2026-10-16

### Added

- *(memory)* add borrowed map lookup ([#86](https://github.com/structured-world/signature-primitives/pull/86))
- *(memory)* add shared immutable strings ([#84](https://github.com/structured-world/signature-primitives/pull/84))

## [0.4.1](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.4.0...structured-pkix-v0.4.1) - 2026-10-16

### Added

- *(memory)* add fallible map filtering ([#79](https://github.com/structured-world/signature-primitives/pull/79))

## [0.4.0](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.3.0...structured-pkix-v0.4.0) - 2026-10-16

### Added

- *(xades)* add baseline validation mechanisms ([#74](https://github.com/structured-world/signature-primitives/pull/74))

## [0.3.0](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.2.4...structured-pkix-v0.3.0) - 2026-10-15

### Fixed

- *(pkix)* retain scoped execution and provenance ([#72](https://github.com/structured-world/signature-primitives/pull/72))

## [0.2.4](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.2.3...structured-pkix-v0.2.4) - 2026-10-14

### Fixed

- *(tsp)* retain carried trailing-data faults ([#69](https://github.com/structured-world/signature-primitives/pull/69))

## [0.2.3](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.2.2...structured-pkix-v0.2.3) - 2026-10-14

### Fixed

- *(tsp)* preserve unique recovery readings ([#66](https://github.com/structured-world/signature-primitives/pull/66))

## [0.2.2](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.2.1...structured-pkix-v0.2.2) - 2026-10-14

### Fixed

- *(cms)* preserve duplicate timestamp identity ([#63](https://github.com/structured-world/signature-primitives/pull/63))

## [0.2.1](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.2.0...structured-pkix-v0.2.1) - 2026-10-14

### Added

- *(pkix)* add algorithm inspection readings ([#60](https://github.com/structured-world/signature-primitives/pull/60))

## [0.2.0](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.1.6...structured-pkix-v0.2.0) - 2026-10-14

### Added

- *(cms)* add bounded CMS and timestamp checks ([#47](https://github.com/structured-world/signature-primitives/pull/47))
- *(pkix)* add bounded value queries ([#49](https://github.com/structured-world/signature-primitives/pull/49))

### Fixed

- *(cms)* share duplicate digest identity ([#56](https://github.com/structured-world/signature-primitives/pull/56))

### Other

- document coordinated CMS consumption ([#54](https://github.com/structured-world/signature-primitives/pull/54))

## [0.1.6](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.1.5...structured-pkix-v0.1.6) - 2026-10-13

### Fixed

- *(pkix)* bound name catalogue construction ([#45](https://github.com/structured-world/signature-primitives/pull/45))

## [0.1.5](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.1.4...structured-pkix-v0.1.5) - 2026-10-13

### Added

- compare names with shared work ceilings ([#42](https://github.com/structured-world/signature-primitives/pull/42))

## [0.1.4](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.1.3...structured-pkix-v0.1.4) - 2026-10-13

### Added

- *(asn1)* recover integers with diagnostics ([#35](https://github.com/structured-world/signature-primitives/pull/35))

## [0.1.3](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.1.2...structured-pkix-v0.1.3) - 2026-10-13

### Added

- *(pkix)* add CRL and OCSP evidence ([#30](https://github.com/structured-world/signature-primitives/pull/30))

### Other

- update audited allocation dependencies ([#32](https://github.com/structured-world/signature-primitives/pull/32))

## [0.1.2](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.1.1...structured-pkix-v0.1.2) - 2026-10-12

### Fixed

- *(time)* read constructed GeneralizedTime ([#28](https://github.com/structured-world/signature-primitives/pull/28))

## [0.1.1](https://github.com/structured-world/signature-primitives/compare/structured-pkix-v0.1.0...structured-pkix-v0.1.1) - 2026-10-12

### Added

- *(pkix)* expose policy qualifier validation ([#23](https://github.com/structured-world/signature-primitives/pull/23))
- *(pkix)* add rfc4514 name selectors ([#19](https://github.com/structured-world/signature-primitives/pull/19))
- *(pkix)* check supplied certificate paths ([#17](https://github.com/structured-world/signature-primitives/pull/17))

### Other

- *(pkix)* make policy exhaustion deterministic ([#21](https://github.com/structured-world/signature-primitives/pull/21))
- improve crate discovery and quick starts ([#15](https://github.com/structured-world/signature-primitives/pull/15))
