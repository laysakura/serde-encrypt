# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog][Keep a Changelog] and this project adheres to [Semantic Versioning][Semantic Versioning].

## [Unreleased]

### Changed

- Some `struct`s/`enum`s moved into differently named modules. Shows where into they are moved.
  - `serde_encrypt::Error`
  - `serde_encrypt::ErrorKind`
  - `serde_encrypt::EncryptedMessages`
  - `serde_encrypt::SenderCombinedKey`
  - `serde_encrypt::ReceiverCombinedKey`
  - `serde_encrypt::SenderKeyPair`
  - `serde_encrypt::ReceiverKeyPair`
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
