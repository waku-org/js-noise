import { ChaCha20Poly1305 } from "@stablelib/chacha20poly1305";

import { bytes32 } from "./@types/basic.js";
import { Cipher } from "./crypto.js";

export class ChaChaPoly implements Cipher {
  encrypt(k: bytes32, n: Uint8Array, ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    const ctx = new ChaCha20Poly1305(k);
    return ctx.seal(n, plaintext, ad);
  }

  decrypt(k: bytes32, n: Uint8Array, ad: Uint8Array, ciphertext: Uint8Array): Uint8Array | null {
    const ctx = new ChaCha20Poly1305(k);
    return ctx.open(n, ciphertext, ad);
  }
}
