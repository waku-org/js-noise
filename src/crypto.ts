import { ChaCha20Poly1305, TAG_LENGTH } from "@stablelib/chacha20poly1305";
import { HKDF } from "@stablelib/hkdf";
import { hash, SHA256 } from "@stablelib/sha256";
import * as x25519 from "@stablelib/x25519";
import { concat as uint8ArrayConcat } from "uint8arrays/concat";

import type { bytes, bytes32 } from "./@types/basic.js";
import type { Hkdf } from "./@types/handshake.js";
import type { KeyPair } from "./@types/keypair.js";

export const Curve25519KeySize = x25519.PUBLIC_KEY_LENGTH;
export const ChachaPolyTagLen = TAG_LENGTH;

export function hashSHA256(data: Uint8Array): Uint8Array {
  return hash(data);
}

export function intoCurve25519Key(s: Uint8Array): bytes32 {
  if (s.length != x25519.PUBLIC_KEY_LENGTH) {
    throw new Error("invalid public key length");
  }

  return s;
}

export function getHKDF(ck: bytes32, ikm: Uint8Array): Hkdf {
  const hkdf = new HKDF(SHA256, ikm, ck);
  const okmU8Array = hkdf.expand(96);
  const okm = okmU8Array;

  const k1 = okm.subarray(0, 32);
  const k2 = okm.subarray(32, 64);
  const k3 = okm.subarray(64, 96);

  return [k1, k2, k3];
}

export function getHKDFRaw(ck: bytes32, ikm: Uint8Array, numBytes: number): Uint8Array {
  const hkdf = new HKDF(SHA256, ikm, ck);
  return hkdf.expand(numBytes);
}

export function generateX25519KeyPair(): KeyPair {
  const keypair = x25519.generateKeyPair();

  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.secretKey,
  };
}

export function generateX25519KeyPairFromSeed(seed: Uint8Array): KeyPair {
  const keypair = x25519.generateKeyPairFromSeed(seed);

  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.secretKey,
  };
}

export function generateX25519SharedKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.sharedKey(privateKey, publicKey);
}

export function chaCha20Poly1305Encrypt(plaintext: Uint8Array, nonce: Uint8Array, ad: Uint8Array, k: bytes32): bytes {
  const ctx = new ChaCha20Poly1305(k);

  return ctx.seal(nonce, plaintext, ad);
}

export function chaCha20Poly1305Decrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
  k: bytes32
): bytes | null {
  const ctx = new ChaCha20Poly1305(k);

  return ctx.open(nonce, ciphertext, ad);
}

export function dh(privateKey: bytes32, publicKey: bytes32): bytes32 {
  try {
    const derivedU8 = generateX25519SharedKey(privateKey, publicKey);

    if (derivedU8.length === 32) {
      return derivedU8;
    }

    return derivedU8.subarray(0, 32);
  } catch (e) {
    console.error(e);
    return new Uint8Array(32);
  }
}

//  Commits a public key pk for randomness r as H(pk || s)
export function commitPublicKey(publicKey: bytes32, r: Uint8Array): bytes32 {
  return hashSHA256(uint8ArrayConcat([publicKey, r]));
}
