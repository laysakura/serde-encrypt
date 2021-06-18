# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog][Keep a Changelog] and this project adheres to [Semantic Versioning][Semantic Versioning].

## [Unreleased]

## [v0.5.0] - 2021-06-19

### Changed

- `SharedKey` serializer - `BincodeSerializer` for std; `PostcardSerilizer` for no_std. [#94](https://github.com/laysakura/serde-encrypt/pull/90)

### Fixed

- Documentation about serializers. Although `BincodeSerializer` or `PostcardSerializer` show better performance, `CborSerializer` serializes more complex serde types. [#94](https://github.com/laysakura/serde-encrypt/pull/90)

## [v0.4.1] - 2021-06-19

### Fixed

- Dead links in documents. [#90](https://github.com/laysakura/serde-encrypt/pull/90), [#93](https://github.com/laysakura/serde-encrypt/pull/93)

## [v0.4.0] - 2021-06-17

### Added

- New built-in serializers:
  - `PostcardSerializer`, which uses [`postcard` crate](https://docs.rs/postcard) for serialization.
  - `BincodeSerializer` for `std` feature, which uses [`bincode` crate](https://docs.rs/bincode) for serialization.

- `EncryptedMessage::len()` function to return cipher-text's payload size.

## [v0.3.2] - 2021-06-16

### Added

- [`serde-encrypt-sgx` crate](https://github.com/laysakura/serde-encrypt-sgx) for crates using [Rust SGX SDK](https://github.com/apache/incubator-teaclave-sgx-sdk).

- Minimum Supported Rust Version decreases to 1.49.0.

### Changed

- `serde-encrypt` crate is split into `serde-encrypt-core` (no dependencies to serde) and `serde-encrypt` (serde dependent layer). Users should depend only on `serde-encrypt` (structures from `-core` are re-exported).

- `SerdeEncryptPublicKey` and `SerdeEncryptSharedKey` takes associated type `S` (serializer). Currently `CborSerializer` is available. Crate users can implement serializers by themselves if necessary.

- Some `struct`s/`enum`s moved into differently named modules. Shows where into they are moved.
  - `serde_encrypt::Error`
  - `serde_encrypt::ErrorKind`
  - `serde_encrypt::EncryptedMessages`
  - `serde_encrypt::SenderCombinedKey`
  - `serde_encrypt::ReceiverCombinedKey`
  - `serde_encrypt::AsSharedKey`

## [v0.2.0] - 2021-06-14

### Added

- `EncryptedMessage::nonce()` getter method.
- `EncryptedMessage::encrypted()` getter method.

## [v0.1.1] - 2021-06-14

### Added

- Initial release (0.1.0 yanked)

---

<!-- Links -->
[Keep a Changelog]: https://keepachangelog.com/
[Semantic Versioning]: https://semver.org/

<!-- Versions -->
[Unreleased]: https://github.com/laysakura/serde-encrypt/compare/v0.5.0...HEAD
[Released]: https://github.com/laysakura/serde-encrypt/releases
[v0.5.0]: https://github.com/laysakura/serde-encrypt/compare/v0.4.1...v0.5.0
[v0.4.1]: https://github.com/laysakura/serde-encrypt/compare/v0.4.0...v0.4.1
[v0.4.0]: https://github.com/laysakura/serde-encrypt/compare/v0.3.2...v0.4.0
[v0.3.2]: https://github.com/laysakura/serde-encrypt/compare/0.2.0...v0.3.2
[v0.2.0]: https://github.com/laysakura/serde-encrypt/compare/0.1.1...0.2.0
[v0.1.1]: https://github.com/laysakura/serde-encrypt/releases/0.1.1
