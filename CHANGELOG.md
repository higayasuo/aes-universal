# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2025-06-02

### Changed

- Renamed package from `expo-aes-universal` to `aes-universal`
- Updated all import paths in documentation to reflect the new package name
- Removed dependency on `expo-crypto-universal` as the library now provides its own unified interface for `getRandomBytes` across web and native platforms

## [0.1.2] - 2025-04-18

### Added

- Added encryption data serialization utilities using CBOR
  - `encodeEncryptionData`: Serializes encryption components into a single Uint8Array
  - `decodeEncryptionData`: Deserializes encoded data back into encryption components

### Changed

- Added length validation for cryptographic parameters in AbstractCbcCipher and AbstractGcmCipher
  - CEK (Content Encryption Key) length validation
  - Tag length validation
  - IV (Initialization Vector) length validation

## [0.1.1] - 2025-04-16

### Changed

- Moved Web/Native/Node implementations to separate projects:
  - Web implementation moved to expo-aes-universal-web
  - Native implementation moved to expo-aes-universal-native
  - Node implementation moved to expo-aes-universal-node

## [Unreleased]

### Added

- Initial implementation of AES encryption/decryption library
- Support for CBC mode with HMAC (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512)
- Support for GCM mode (A128GCM, A192GCM, A256GCM)
- Web implementation using Web Crypto API
- Native implementation using forge
- Comprehensive test suite
- TypeScript support
