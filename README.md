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

## Usage

```typescript
import { Aes } from 'expo-aes-universal';
import { getCryptoModule } from 'expo-crypto-universal';

// Get CryptoModule
const cryptoModule = getCryptoModule();
const aes = new Aes(cryptoModule);

// Define encryption algorithm
const enc = 'A128CBC-HS256'; // or 'A192CBC-HS384', 'A256CBC-HS512', 'A128GCM', 'A192GCM', 'A256GCM'

// Generate random CEK
const cek = cryptoModule.getRandomBytes(32); // 32 bytes for A128CBC-HS256

// Define AAD (Additional Authenticated Data)
const aad = new Uint8Array([4, 5, 6]);

// Encrypt data
const encrypted = await aes.encrypt({
  enc,
  cek,
  plaintext: new Uint8Array([1, 2, 3]),
  aad,
});

// Decrypt data
const decrypted = await aes.decrypt({
  enc,
  cek,
  ciphertext: encrypted.ciphertext,
  tag: encrypted.tag,
  iv: encrypted.iv,
  aad,
});
```

## Supported Algorithms

### CBC Mode with HMAC

- `A128CBC-HS256`: AES-128-CBC with HMAC-SHA-256
- `A192CBC-HS384`: AES-192-CBC with HMAC-SHA-384
- `A256CBC-HS512`: AES-256-CBC with HMAC-SHA-512

### GCM Mode

- `A128GCM`: AES-128-GCM
- `A192GCM`: AES-192-GCM
- `A256GCM`: AES-256-GCM

## Platform Support

- Web: Uses Web Crypto API
- Native: Uses forge library

The library automatically selects the appropriate implementation based on the platform.

## Peer Dependencies

This library has the following peer dependencies:

- `node-forge`: Required for native implementation
- `expo-crypto`: Required by `expo-crypto-universal` for native implementation

You need to install these dependencies in your project:

```bash
npm install node-forge expo-crypto
```

Even if you only use the web implementation, these dependencies are required for installation. However, they are only used when running on native platforms.

## Testing

When testing with Vitest, you may encounter the following error:

```
Error: Expected 'from', got 'typeof'
```

To resolve this, add the following mock to your test file:

```typescript
import { vi } from 'vitest';

// Mock expo-crypto
vi.mock('expo-crypto', () => ({}));
```

This mock is necessary because `expo-crypto-universal` has `expo-crypto` as a peer dependency.

## License

MIT
