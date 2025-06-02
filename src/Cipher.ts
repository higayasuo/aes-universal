import { Enc } from './Enc';

export type EncryptArgs = {
  enc: Enc;
  plaintext: Uint8Array;
  cek: Uint8Array;
  aad: Uint8Array;
};

export type EncryptResult = {
  ciphertext: Uint8Array;
  tag: Uint8Array;
  iv: Uint8Array;
};

export type DecryptArgs = {
  enc: string;
  cek: Uint8Array;
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
  aad: Uint8Array;
};

export interface Cipher {
  encrypt: (args: EncryptArgs) => Promise<EncryptResult>;

  decrypt: (args: DecryptArgs) => Promise<Uint8Array>;
}
