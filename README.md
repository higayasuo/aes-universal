# expo-aes-universal

A universal AES encryption/decryption library for Expo applications that works on both web and native platforms.

## Features

- Supports AES encryption algorithms:
  - CBC mode with HMAC: A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
  - GCM mode: A128GCM, A192GCM, A256GCM
- Web implementation using Web Crypto API
- Native implementation using forge
- Consistent behavior across platforms
- TypeScript support

## Installation

```bash
npm install expo-aes-universal
```

## Peer Dependencies

This package requires the following peer dependencies:

- `expo-crypto-universal`: The base package that defines the crypto interfaces
- `expo-crypto-universal-web`: Provides Web Crypto API implementation
- `expo-crypto-universal-native`: Provides native crypto implementation
- `expo-aes-universal-web`: Web implementation
- `expo-aes-universal-native`: Native implementation

```bash
npm install expo-crypto-universal expo-crypto-universal-web expo-crypto-universal-native expo-aes-universal-web expo-aes-universal-native
```

## AES-128

### CBC Mode (A128CBC-HS256)

In CBC mode, the Content Encryption Key (CEK) includes both the encryption key and the MAC key:

- A128CBC-HS256: 32 bytes (16 bytes for encryption + 16 bytes for MAC)

```typescript
import { isWeb } from 'expo-crypto-universal';
import { WebCryptoModule } from 'expo-crypto-universal-web';
import { NativeCryptoModule } from 'expo-crypto-universal-native';
import { WebCbcCipher } from 'expo-aes-universal-web';
import { NativeCbcCipher } from 'expo-aes-universal-native';

// Get the appropriate crypto module for your platform
const cryptoModule = isWeb() ? new WebCryptoModule() : new NativeCryptoModule();

// Create cipher instance based on platform
const cipher = isWeb()
  ? new WebCbcCipher(cryptoModule)
  : new NativeCbcCipher(cryptoModule);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Additional authenticated data
const aad = new Uint8Array([5, 6, 7, 8]);

// Generate random CEK for AES-128-CBC-HS256
const cek = cryptoModule.getRandomBytes(32); // 32 bytes (16 for encryption + 16 for MAC)

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A128CBC-HS256', // AES-128 in CBC mode with HMAC-SHA-256
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: 'A128CBC-HS256',
  cek,
  ciphertext,
  tag,
  iv,
  aad, // Must use the same AAD as encryption
});

expect(decrypted).toEqual(plaintext);
```

### GCM Mode (A128GCM)

In GCM mode, the Content Encryption Key (CEK) is used directly for encryption:

- A128GCM: 16 bytes

```typescript
import { isWeb } from 'expo-crypto-universal';
import { WebCryptoModule } from 'expo-crypto-universal-web';
import { NativeCryptoModule } from 'expo-crypto-universal-native';
import { WebGcmCipher } from 'expo-aes-universal-web';
import { NativeGcmCipher } from 'expo-aes-universal-native';

// Get the appropriate crypto module for your platform
const cryptoModule = isWeb() ? new WebCryptoModule() : new NativeCryptoModule();

// Create cipher instance based on platform
const cipher = isWeb()
  ? new WebGcmCipher(cryptoModule)
  : new NativeGcmCipher(cryptoModule);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Additional authenticated data
const aad = new Uint8Array([5, 6, 7, 8]);

// Generate random CEK for AES-128-GCM
const cek = cryptoModule.getRandomBytes(16); // 16 bytes

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A128GCM', // AES-128 in GCM mode
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: 'A128GCM',
  cek,
  ciphertext,
  tag,
  iv,
  aad, // Must use the same AAD as encryption
});

expect(decrypted).toEqual(plaintext);
```

## AES-192

### CBC Mode (A192CBC-HS384)

In CBC mode, the Content Encryption Key (CEK) includes both the encryption key and the MAC key:

- A192CBC-HS384: 48 bytes (24 bytes for encryption + 24 bytes for MAC)

```typescript
// Create cipher instance based on platform
const cipher = isWeb()
  ? new WebCbcCipher(cryptoModule)
  : new NativeCbcCipher(cryptoModule);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Additional authenticated data
const aad = new Uint8Array([5, 6, 7, 8]);

// Generate random CEK for AES-192-CBC-HS384
const cek = cryptoModule.getRandomBytes(48); // 48 bytes (24 for encryption + 24 for MAC)

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A192CBC-HS384', // AES-192 in CBC mode with HMAC-SHA-384
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: 'A192CBC-HS384',
  cek,
  ciphertext,
  tag,
  iv,
  aad, // Must use the same AAD as encryption
});

expect(decrypted).toEqual(plaintext);
```

### GCM Mode (A192GCM)

In GCM mode, the Content Encryption Key (CEK) is used directly for encryption:

- A192GCM: 24 bytes

```typescript
// Create cipher instance based on platform
const cipher = isWeb()
  ? new WebGcmCipher(cryptoModule)
  : new NativeGcmCipher(cryptoModule);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Additional authenticated data
const aad = new Uint8Array([5, 6, 7, 8]);

// Generate random CEK for AES-192-GCM
const cek = cryptoModule.getRandomBytes(24); // 24 bytes

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A192GCM', // AES-192 in GCM mode
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: 'A192GCM',
  cek,
  ciphertext,
  tag,
  iv,
  aad, // Must use the same AAD as encryption
});

expect(decrypted).toEqual(plaintext);
```

## AES-256

### CBC Mode (A256CBC-HS512)

In CBC mode, the Content Encryption Key (CEK) includes both the encryption key and the MAC key:

- A256CBC-HS512: 64 bytes (32 bytes for encryption + 32 bytes for MAC)

```typescript
// Create cipher instance based on platform
const cipher = isWeb()
  ? new WebCbcCipher(cryptoModule)
  : new NativeCbcCipher(cryptoModule);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Additional authenticated data
const aad = new Uint8Array([5, 6, 7, 8]);

// Generate random CEK for AES-256-CBC-HS512
const cek = cryptoModule.getRandomBytes(64); // 64 bytes (32 for encryption + 32 for MAC)

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A256CBC-HS512', // AES-256 in CBC mode with HMAC-SHA-512
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: 'A256CBC-HS512',
  cek,
  ciphertext,
  tag,
  iv,
  aad, // Must use the same AAD as encryption
});

expect(decrypted).toEqual(plaintext);
```

### GCM Mode (A256GCM)

In GCM mode, the Content Encryption Key (CEK) is used directly for encryption:

- A256GCM: 32 bytes

```typescript
// Create cipher instance based on platform
const cipher = isWeb()
  ? new WebGcmCipher(cryptoModule)
  : new NativeGcmCipher(cryptoModule);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Additional authenticated data
const aad = new Uint8Array([5, 6, 7, 8]);

// Generate random CEK for AES-256-GCM
const cek = cryptoModule.getRandomBytes(32); // 32 bytes

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A256GCM', // AES-256 in GCM mode
  cek,
  plaintext,
  aad, // Must use the same AAD for decryption
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: 'A256GCM',
  cek,
  ciphertext,
  tag,
  iv,
  aad, // Must use the same AAD as encryption
});

expect(decrypted).toEqual(plaintext);
```

## Encryption Data Serialization

The library provides utilities for serializing and deserializing encryption data using CBOR (Concise Binary Object Representation).

```typescript
import { encodeEncryptionData, decodeEncryptionData } from 'expo-aes-universal';

// After encryption
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A128GCM',
  cek,
  plaintext,
  aad,
});

// Serialize encryption data
const serialized = encodeEncryptionData({
  ciphertext,
  iv,
  tag,
  aad,
});

// Store serialized data in database or file
// ...

// Later, deserialize the data
const deserialized = decodeEncryptionData(serialized);

// Use deserialized data for decryption
const decrypted = await cipher.decrypt({
  enc: 'A128GCM',
  cek,
  ciphertext: deserialized.ciphertext,
  tag: deserialized.tag,
  iv: deserialized.iv,
  aad: deserialized.aad,
});
```

The `encodeEncryptionData` function takes an object containing the encryption components and returns a single `Uint8Array` encoded in CBOR format. The `decodeEncryptionData` function takes the encoded data and returns the original encryption components.

This serialization method is particularly useful when you need to store encrypted data in a database or file, as it combines all the necessary components into a single binary format.

## Platform Support

- Web: Uses Web Crypto API
- Native: Uses forge library

The library automatically selects the appropriate implementation based on the platform.

## License

MIT
