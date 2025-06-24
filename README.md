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

The library provides platform-specific implementations that automatically handle both CBC and GCM encryption modes. The `generateCek` method automatically generates the correct key length for each encryption mode. The `Cipher` interface includes a `randomBytes` property that provides access to the random bytes generation function used by the cipher.

```typescript
import { WebAesCipher } from 'aes-universal-web';
import { NativeAesCipher } from 'aes-universal-native';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { nativeCryptoModule } from 'expo-crypto-universal-native';

const isWeb = typeof crypto?.getRandomValues === 'function';
const randomBytes = isWeb
  ? webCryptoModule.getRandomBytes
  : nativeCryptoModule.getRandomBytes;

// Create cipher instance based on platform
const cipher = isWeb
  ? new WebAesCipher(randomBytes)
  : new NativeAesCipher(randomBytes);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Additional authenticated data
const aad = new Uint8Array([5, 6, 7, 8]);

// Define encryption modes
const cbcEnc = 'A128CBC-HS256';
const gcmEnc = 'A128GCM';

// Generate CEK for CBC mode
const cek = cipher.generateCek(cbcEnc); // Automatically generates 32 bytes (16 for encryption + 16 for MAC)

// Encrypt data using CBC mode
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: cbcEnc,
  cek,
  plaintext,
  aad,
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: cbcEnc,
  cek,
  ciphertext,
  tag,
  iv,
  aad,
});

expect(decrypted).toEqual(plaintext);

// The same cipher instance can be used for GCM mode
const gcmCek = cipher.generateCek(gcmEnc); // Automatically generates 16 bytes

const gcmResult = await cipher.encrypt({
  enc: gcmEnc,
  cek: gcmCek,
  plaintext,
  aad,
});

const gcmDecrypted = await cipher.decrypt({
  enc: gcmEnc,
  cek: gcmCek,
  ciphertext: gcmResult.ciphertext,
  tag: gcmResult.tag,
  iv: gcmResult.iv,
  aad,
});

expect(gcmDecrypted).toEqual(plaintext);
```

## Key Lengths

The library automatically handles key lengths for different encryption modes:

### CBC Mode

- A128CBC-HS256: 32 bytes (16 for encryption + 16 for MAC)
- A192CBC-HS384: 48 bytes (24 for encryption + 24 for MAC)
- A256CBC-HS512: 64 bytes (32 for encryption + 32 for MAC)

### GCM Mode

- A128GCM: 16 bytes
- A192GCM: 24 bytes
- A256GCM: 32 bytes

## Error Messages

The library provides detailed error messages to help with debugging:

### CBC Mode

- Content Encryption Key (CEK) length errors:

  ```
  Invalid CBC content encryption key length: expected {expectedLength} bytes ({keyBits} bits), but got {actualLength} bytes
  ```

- Initialization Vector (IV) length errors:

  ```
  Invalid CBC IV length: expected 16 bytes, got {actualLength} bytes
  ```

- Authentication Tag length errors:
  ```
  Invalid CBC authentication tag length: expected {expectedLength} bytes ({keyBits} bits), but got {actualLength} bytes
  ```

### GCM Mode

- Content Encryption Key (CEK) length errors:

  ```
  Invalid GCM content encryption key length: expected {expectedLength} bytes ({keyBits} bits), but got {actualLength} bytes
  ```

- Initialization Vector (IV) length errors:

  ```
  Invalid GCM IV length: expected 12 bytes, got {actualLength} bytes
  ```

- Authentication Tag length errors:
  ```
  Invalid GCM authentication tag length: expected 16 bytes, but got {actualLength} bytes
  ```

## Platform Support

- Web: Uses Web Crypto API
- Native: Uses forge library

The library automatically selects the appropriate implementation based on the platform.

## License

MIT
