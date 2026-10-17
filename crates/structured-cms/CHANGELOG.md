# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.3](https://github.com/structured-world/signature-primitives/compare/v0.6.2...v0.6.3) - 2026-10-17

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
