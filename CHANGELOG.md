# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.7] - 2025-06-04

### Changed

- Renamed `keyBits` to `keyBitLength` for consistency
- Changed parameter type from byte length to bit length in cryptographic functions
  - Now accepting bit length instead of byte length for better clarity and consistency
  - Updated all related functions and tests to use bit length

## [0.1.6] - 2025-06-02

### Changed

- Improved error messages for cryptographic parameter validation
  - Added detailed error messages for CBC mode (CEK, IV, and tag length validation)
  - Added detailed error messages for GCM mode (CEK, IV, and tag length validation)
  - Updated README with comprehensive error message documentation
- Reorganized project structure for better maintainability
  - Moved core cipher interfaces to `src/core`
  - Moved common utilities to `src/common`
  - Moved constants to `src/constants`
  - Added path alias `@` for `src` directory
  - Updated import paths to use the new path alias

## [0.1.5] - 2025-06-02

### Changed

- Bump version to 0.1.5

## [0.1.4] - 2025-06-02

### Added

- Added export of types from the main entry point (`export * from './types'`)

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

## [0.1.0] - 2025-04-16

### Added

- Initial implementation of AES encryption/decryption library
- Support for CBC mode with HMAC (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512)
- Support for GCM mode (A128GCM, A192GCM, A256GCM)
- Web implementation using Web Crypto API
- Native implementation using forge
- Comprehensive test suite
- TypeScript support
