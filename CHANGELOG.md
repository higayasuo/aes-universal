# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
