# Changelog

All notable changes to this project will be documented in this file. Changes to the [tlock crate](../tlock/CHANGELOG.md) also apply to the tlock_age crate, and are not duplicated here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Update dependencies
- Update Rust to 1.74

## [0.0.3] - 2023-07-23

### Fixed

- Fix all panic with error handling

### Changed

- Update age dependency to 0.9
- Update errors from anyhow to library errors
- Update examples to use drand_core v0.0.7
- Update benchmark with distinct lock/unlock measurements

## [0.0.2] - 2023-03-27

### Changed

- Update BLS12-381 library to improve performance

## [0.0.1] - 2023-03-22

### Added

- Timelock encryption and decryption in the age format
- ASCII Armor
- tlock header decryption
- Encryption with public key on G1 and G2
- Interroperability with [Go](https://github.com/drand/tlock) and [JS](https://github.com/drand/tlock-js) implementation
- wasm32 compatible library
