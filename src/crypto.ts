import { Hash } from "@stablelib/hash";
import { HKDF as hkdf } from "@stablelib/hkdf";
import { RandomSource } from "@stablelib/random";
import { concat as uint8ArrayConcat } from "uint8arrays/concat";

import type { bytes32 } from "./@types/basic.js";
import type { KeyPair } from "./@types/keypair.js";
import { Nonce } from "./nonce.js";

/**
 * HKDF key derivation function
 * @param ck chaining key
 * @param ikm input key material
 * @param length length of each generated key
 * @param numKeys number of keys to generate
 * @returns array  of `numValues` length containing Uint8Array keys of a given byte `length`
 */
export function HKDF(
  hash: new () => Hash,
  ck: bytes32,
  ikm: Uint8Array,
  length: number,
  numKeys: number
): Array<Uint8Array> {
  const numBytes = length * numKeys;
  const okm = new hkdf(hash, ikm, ck).expand(numBytes);
  const result = [];
  for (let i = 0; i < numBytes; i += length) {
    const k = okm.subarray(i, i + length);
    result.push(k);
  }
  return result;
}

export function hash(hash: new () => Hash, data: Uint8Array): bytes32 {
  const h = new hash();
  h.update(data);
  const digest = h.digest();
  h.clean();
  return digest;
}

/**
 * Generates a random static key commitment using a public key pk for randomness r as H(pk || s)
 * @param h Hash function
 * @param publicKey x25519 public key
 * @param r random fixed-length value
 * @returns 32 byte hash
 */
export function commitPublicKey(h: new () => Hash, publicKey: bytes32, r: Uint8Array): bytes32 {
  const data = uint8ArrayConcat([publicKey, r]);
  return hash(h, data);
}

/**
 * Represents a Cipher
 */
export interface Cipher {
  /**
   * Encrypt and authenticate data
   * @param k 32-byte key
   * @param n 12 byte little-endian nonce
   * @param ad associated data
   * @param plaintext data to encrypt
   * @returns sealed ciphertext including authentication tag
   */
  encrypt(k: bytes32, n: Nonce, ad: Uint8Array, plaintext: Uint8Array): Uint8Array;

  /**
   * Authenticate and decrypt data
   * @param k 32-byte key
   * @param n 12 byte little-endian nonce
   * @param ad associated data
   * @param ciphertext data to decrypt
   * @returns plaintext if decryption was successful, `null` otherwise
   */
  decrypt(k: bytes32, n: Nonce, ad: Uint8Array, ciphertext: Uint8Array): Uint8Array | null;
}

/**
 * Represents a key uses for Diffie–Hellman key exchange
 */
export interface DHKey {
  /**
   * Convert an Uint8Array into a 32-byte value. If the input data length is different
   * from 32, throw an error. This is used mostly as a validation function to ensure
   * that an Uint8Array represents a valid key
   * @param s input data
   * @return 32-byte key
   */
  intoKey(s: Uint8Array): bytes32;

  /**
   * Get key length
   */
  DHLen(): number;

  /**
   * Perform a Diffie–Hellman key exchange
   * @param privateKey private key
   * @param publicKey public key
   * @returns shared secret
   */
  DH(privateKey: bytes32, publicKey: bytes32): bytes32;

  /**
   * Generate a random keypair
   * @returns Keypair
   */
  generateKeyPair(prng?: RandomSource): KeyPair;

  /**
   * Generate keypair using an input seed
   * @param seed 32-byte secret
   * @returns Keypair
   */
  generateKeyPairFromSeed(seed: bytes32): KeyPair;
}
