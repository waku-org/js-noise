import * as x25519 from "@stablelib/x25519";

import type { bytes32 } from "./@types/basic.js";
import type { KeyPair } from "./@types/keypair.js";
import { DHKey } from "./crypto.js";

export class DH25519 implements DHKey {
  intoKey(s: Uint8Array): bytes32 {
    if (s.length != x25519.PUBLIC_KEY_LENGTH) {
      throw new Error("invalid public key length");
    }

    return s;
  }

  generateKeyPair(): KeyPair {
    const keypair = x25519.generateKeyPair();

    return {
      publicKey: keypair.publicKey,
      privateKey: keypair.secretKey,
    };
  }

  generateKeyPairFromSeed(seed: bytes32): KeyPair {
    const keypair = x25519.generateKeyPairFromSeed(seed);

    return {
      publicKey: keypair.publicKey,
      privateKey: keypair.secretKey,
    };
  }

  DH(privateKey: bytes32, publicKey: bytes32): bytes32 {
    try {
      const derivedU8 = x25519.sharedKey(privateKey, publicKey);

      if (derivedU8.length === 32) {
        return derivedU8;
      }

      return derivedU8.subarray(0, 32);
    } catch (e) {
      console.error(e);
      return new Uint8Array(32);
    }
  }

  DHLen(): number {
    return x25519.PUBLIC_KEY_LENGTH;
  }
}
