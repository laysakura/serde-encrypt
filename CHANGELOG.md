# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog][Keep a Changelog] and this project adheres to [Semantic Versioning][Semantic Versioning].

## [Unreleased]

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

---

## [Released]

## [0.2.0] - 2021-06-14

### Added

- `EncryptedMessage::nonce()` getter method.
- `EncryptedMessage::encrypted()` getter method.

## [0.1.1] - 2021-06-14

### Added

- Initial release (0.1.0 yanked)

---

<!-- Links -->
[Keep a Changelog]: https://keepachangelog.com/
[Semantic Versioning]: https://semver.org/

<!-- Versions -->
[Unreleased]: https://github.com/laysakura/serde-encrypt/compare/0.1.1...HEAD
[Released]: https://github.com/laysakura/serde-encrypt/releases
[0.2.0]: https://github.com/laysakura/serde-encrypt/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/laysakura/serde-encrypt/releases/0.1.1
