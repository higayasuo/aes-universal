# aes-universal

A universal AES encryption/decryption library that works on both web and native platforms.

## Features

- Supports AES encryption algorithms:
  - CBC mode with HMAC: A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
  - GCM mode: A128GCM, A192GCM, A256GCM
- Web implementation using Web Crypto API
- Native implementation using forge
- Consistent behavior across platforms
- TypeScript support
- Detailed error messages for debugging
- Automatic CEK generation with correct key lengths

## Installation

```bash
npm install aes-universal
```

## Peer Dependencies

This package requires the following peer dependencies:

- `@noble/hashes`: For cryptographic hash functions
- `u8a-utils`: For Uint8Array utilities
- `aes-universal-web`: Web implementation
- `aes-universal-native`: Native implementation

## Usage

The library provides platform-specific implementations that automatically handle both CBC and GCM encryption modes. Use `getCekByteLength` and `getIvByteLength` methods to get the required byte lengths for each encryption mode, then generate the keys and IVs using a secure random bytes generator.

```typescript
import { webAesCipher } from 'aes-universal-web';
import { nativeAesCipher } from 'aes-universal-native';
import { randomBytes } from '@noble/hashes/utils';

const isWeb = typeof crypto?.getRandomValues === 'function';

// Create cipher instance based on platform
const cipher = isWeb ? webAesCipher : nativeAesCipher;

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Additional authenticated data
const aad = new Uint8Array([5, 6, 7, 8]);

// Define encryption modes
const cbcEnc = 'A128CBC-HS256';
const gcmEnc = 'A128GCM';

// Generate CEK for CBC mode
const cbcCek = randomBytes(cipher.getCekByteLength(cbcEnc)); // generates 32 bytes (16 for encryption + 16 for MAC)
// Generate IV for CBC mode
const cbcIv = randomBytes(cipher.getIvByteLength(cbcEnc)); // generates 16 bytes

// Encrypt data using CBC mode
const { ciphertext, tag } = await cipher.encrypt({
  enc: cbcEnc,
  cek: cbcCek,
  plaintext,
  iv: cbcIv,
  aad,
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: cbcEnc,
  cek: cbcCek,
  ciphertext,
  tag,
  iv: cbcIv,
  aad,
});

expect(decrypted).toEqual(plaintext);

// The same cipher instance can be used for GCM mode
// Generate CEK for GCM mode
const gcmCek = randomBytes(cipher.getCekByteLength(gcmEnc)); // generates 16 bytes
// Generate IV for GCM mode
const gcmIv = randomBytes(cipher.getIvByteLength(gcmEnc)); // generates 12 bytes

// Encrypt data using GCM mode
const gcmResult = await cipher.encrypt({
  enc: gcmEnc,
  cek: gcmCek,
  plaintext,
  iv: gcmIv,
  aad,
});

// Decrypt data
const gcmDecrypted = await cipher.decrypt({
  enc: gcmEnc,
  cek: gcmCek,
  ciphertext: gcmResult.ciphertext,
  tag: gcmResult.tag,
  iv: gcmIv,
  aad,
});

expect(gcmDecrypted).toEqual(plaintext);
```

## Required Lengths

The library provides `getCekByteLength` and `getIvByteLength` methods to get the required byte lengths for each encryption mode. Use these methods with a secure random bytes generator to create keys and IVs.

### CBC Mode

**Content Encryption Key (CEK) lengths:**

- A128CBC-HS256: 32 bytes (16 for encryption + 16 for MAC)
- A192CBC-HS384: 48 bytes (24 for encryption + 24 for MAC)
- A256CBC-HS512: 64 bytes (32 for encryption + 32 for MAC)

**Initialization Vector (IV) length:**

- All CBC modes: 16 bytes

### GCM Mode

**Content Encryption Key (CEK) lengths:**

- A128GCM: 16 bytes
- A192GCM: 24 bytes
- A256GCM: 32 bytes

**Initialization Vector (IV) length:**

- All GCM modes: 12 bytes

## Platform Support

- Web: Uses Web Crypto API
- Native: Uses forge library

## License

MIT
