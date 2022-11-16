import { fromString as uint8ArrayFromString } from "uint8arrays";
import { concat as uint8ArrayConcat } from "uint8arrays/concat";
import { equals as uint8ArrayEquals } from "uint8arrays/equals";

import type { bytes32 } from "./@types/basic.js";
import { chaCha20Poly1305Decrypt, chaCha20Poly1305Encrypt, getHKDF, hashSHA256 } from "./crypto.js";
import { Nonce } from "./nonce.js";
import { HandshakePattern } from "./patterns.js";

// Waku Noise Protocols for Waku Payload Encryption
// Noise module implementing the Noise State Objects and ChaChaPoly encryption/decryption primitives
// See spec for more details:
// https://github.com/vacp2p/rfc/tree/master/content/docs/rfcs/35
//
// Implementation partially inspired by noise-libp2p and js-libp2p-noise
// https://github.com/status-im/nim-libp2p/blob/master/libp2p/protocols/secure/noise.nim
// https://github.com/ChainSafe/js-libp2p-noise

/*
# Noise state machine primitives

# Overview :
# - Alice and Bob process (i.e. read and write, based on their role) each token appearing in a handshake pattern, consisting of pre-message and message patterns;
# - Both users initialize and update according to processed tokens a Handshake State, a Symmetric State and a Cipher State;
# - A preshared key psk is processed by calling MixKeyAndHash(psk);
# - When an ephemeral public key e is read or written, the handshake hash value h is updated by calling mixHash(e); If the handshake expects a psk, MixKey(e) is further called
# - When an encrypted static public key s or a payload message m is read, it is decrypted with decryptAndHash;
# - When a static public key s or a payload message is written, it is encrypted with encryptAndHash;
# - When any Diffie-Hellman token ee, es, se, ss is read or written, the chaining key ck is updated by calling MixKey on the computed secret;
# - If all tokens are processed, users compute two new Cipher States by calling Split;
# - The two Cipher States obtained from Split are used to encrypt/decrypt outbound/inbound messages.

#################################
# Cipher State Primitives
#################################
*/

export function createEmptyKey(): bytes32 {
  return new Uint8Array(32);
}

export function isEmptyKey(k: bytes32): boolean {
  const emptyKey = createEmptyKey();
  return uint8ArrayEquals(emptyKey, k);
}

// The Cipher State as in https://noiseprotocol.org/noise.html#the-cipherstate-object
// Contains an encryption key k and a nonce n (used in Noise as a counter)
export class CipherState {
  k: bytes32;
  // For performance reasons, the nonce is represented as a Nonce object
  // The nonce is treated as a uint64, even though the underlying `number` only has 52 safely-available bits.
  n: Nonce;

  constructor(k: bytes32 = createEmptyKey(), n = new Nonce()) {
    this.k = k;
    this.n = n;
  }

  clone(): CipherState {
    return new CipherState(new Uint8Array(this.k), new Nonce(this.n.getUint64()));
  }

  equals(b: CipherState): boolean {
    return uint8ArrayEquals(this.k, b.getKey()) && this.n.getUint64() == b.getNonce().getUint64();
  }

  // Checks if a Cipher State has an encryption key set
  protected hasKey(): boolean {
    return !isEmptyKey(this.k);
  }

  // Encrypts a plaintext using key material in a Noise Cipher State
  // The CipherState is updated increasing the nonce (used as a counter in Noise) by one
  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    this.n.assertValue();

    let ciphertext = new Uint8Array();

    if (this.hasKey()) {
      // If an encryption key is set in the Cipher state, we proceed with encryption
      ciphertext = chaCha20Poly1305Encrypt(plaintext, this.n.getBytes(), ad, this.k);
      this.n.increment();
      this.n.assertValue();

      console.trace("encryptWithAd", ciphertext, this.n.getUint64() - 1);
    } else {
      // Otherwise we return the input plaintext according to specification http://www.noiseprotocol.org/noise.html#the-cipherstate-object
      ciphertext = plaintext;
      console.debug("encryptWithAd called with no encryption key set. Returning plaintext.");
    }

    return ciphertext;
  }

  // Decrypts a ciphertext using key material in a Noise Cipher State
  // The CipherState is updated increasing the nonce (used as a counter in Noise) by one
  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    this.n.assertValue();

    if (this.hasKey()) {
      const plaintext = chaCha20Poly1305Decrypt(ciphertext, this.n.getBytes(), ad, this.k);
      if (!plaintext) {
        throw new Error("decryptWithAd failed");
      }

      this.n.increment();
      this.n.assertValue();

      return plaintext;
    } else {
      // Otherwise we return the input ciphertext according to specification
      // http://www.noiseprotocol.org/noise.html#the-cipherstate-object
      console.debug("decryptWithAd called with no encryption key set. Returning ciphertext.");
      return ciphertext;
    }
  }

  // Sets the nonce of a Cipher State
  setNonce(nonce: Nonce): void {
    this.n = nonce;
  }

  // Sets the key of a Cipher State
  setCipherStateKey(key: bytes32): void {
    this.k = key;
  }

  // Gets the key of a Cipher State
  getKey(): bytes32 {
    return this.k;
  }

  // Gets the nonce of a Cipher State
  getNonce(): Nonce {
    return this.n;
  }
}

function hashProtocol(name: string): Uint8Array {
  // If protocol_name is less than or equal to HASHLEN bytes in length,
  // sets h equal to protocol_name with zero bytes appended to make HASHLEN bytes.
  // Otherwise sets h = HASH(protocol_name).
  const protocolName = uint8ArrayFromString(name, "utf-8");

  if (protocolName.length <= 32) {
    const h = new Uint8Array(32);
    h.set(protocolName);
    return h;
  } else {
    return hashSHA256(protocolName);
  }
}

// The Symmetric State as in https://noiseprotocol.org/noise.html#the-symmetricstate-object
// Contains a Cipher State cs, the chaining key ck and the handshake hash value h
export class SymmetricState {
  cs: CipherState;
  ck: bytes32; // chaining key
  h: bytes32; // handshake hash
  hsPattern: HandshakePattern;

  constructor(hsPattern: HandshakePattern) {
    this.h = hashProtocol(hsPattern.name);
    this.ck = this.h;
    this.cs = new CipherState();
    this.hsPattern = hsPattern;
  }

  equals(b: SymmetricState): boolean {
    return (
      this.cs.equals(b.cs) &&
      uint8ArrayEquals(this.ck, b.ck) &&
      uint8ArrayEquals(this.h, b.h) &&
      this.hsPattern.equals(b.hsPattern)
    );
  }

  clone(): SymmetricState {
    const ss = new SymmetricState(this.hsPattern);
    ss.cs = this.cs.clone();
    ss.ck = new Uint8Array(this.ck);
    ss.h = new Uint8Array(this.h);
    return ss;
  }

  // MixKey as per Noise specification http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
  // Updates a Symmetric state chaining key and symmetric state
  mixKey(inputKeyMaterial: Uint8Array): void {
    // We derive two keys using HKDF
    const [ck, tempK] = getHKDF(this.ck, inputKeyMaterial);
    // We update ck and the Cipher state's key k using the output of HDKF
    this.cs = new CipherState(tempK);
    this.ck = ck;
    console.trace("mixKey", this.ck, this.cs.k);
  }

  // MixHash as per Noise specification http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
  // Hashes data into a Symmetric State's handshake hash value h
  mixHash(data: Uint8Array): void {
    // We hash the previous handshake hash and input data and store the result in the Symmetric State's handshake hash value
    this.h = hashSHA256(uint8ArrayConcat([this.h, data]));
    console.trace("mixHash", this.h);
  }

  // mixKeyAndHash as per Noise specification http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
  // Combines MixKey and MixHash
  mixKeyAndHash(inputKeyMaterial: Uint8Array): void {
    // Derives 3 keys using HKDF, the chaining key and the input key material
    const [tmpKey0, tmpKey1, tmpKey2] = getHKDF(this.ck, inputKeyMaterial);
    // Sets the chaining key
    this.ck = tmpKey0;
    // Updates the handshake hash value
    this.mixHash(tmpKey1);
    // Updates the Cipher state's key
    // Note for later support of 512 bits hash functions: "If HASHLEN is 64, then truncates tempKeys[2] to 32 bytes."
    this.cs = new CipherState(tmpKey2);
  }

  // EncryptAndHash as per Noise specification http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
  // Combines encryptWithAd and mixHash
  // Note that by setting extraAd, it is possible to pass extra additional data that will be concatenated to the ad specified by Noise (can be used to authenticate messageNametag)
  encryptAndHash(plaintext: Uint8Array, extraAd: Uint8Array = new Uint8Array()): Uint8Array {
    // The additional data
    const ad = uint8ArrayConcat([this.h, extraAd]);
    // Note that if an encryption key is not set yet in the Cipher state, ciphertext will be equal to plaintext
    const ciphertext = this.cs.encryptWithAd(ad, plaintext);
    // We call mixHash over the result
    this.mixHash(ciphertext);

    return ciphertext;
  }

  // DecryptAndHash as per Noise specification http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
  // Combines decryptWithAd and mixHash
  decryptAndHash(ciphertext: Uint8Array, extraAd: Uint8Array = new Uint8Array()): Uint8Array {
    // The additional data
    const ad = uint8ArrayConcat([this.h, extraAd]);
    // Note that if an encryption key is not set yet in the Cipher state, plaintext will be equal to ciphertext
    const plaintext = this.cs.decryptWithAd(ad, ciphertext);
    // According to specification, the ciphertext enters mixHash (and not the plaintext)
    this.mixHash(ciphertext);

    return plaintext;
  }

  // Split as per Noise specification http://www.noiseprotocol.org/noise.html#the-symmetricstate-object
  // Once a handshake is complete, returns two Cipher States to encrypt/decrypt outbound/inbound messages
  split(): { cs1: CipherState; cs2: CipherState } {
    // Derives 2 keys using HKDF and the chaining key
    const [tmpKey1, tmpKey2] = getHKDF(this.ck, new Uint8Array(0));
    // Returns a tuple of two Cipher States initialized with the derived keys
    return {
      cs1: new CipherState(tmpKey1),
      cs2: new CipherState(tmpKey2),
    };
  }

  // Gets the chaining key field of a Symmetric State
  getChainingKey(): bytes32 {
    return this.ck;
  }

  // Gets the handshake hash field of a Symmetric State
  getHandshakeHash(): bytes32 {
    return this.h;
  }

  // Gets the Cipher State field of a Symmetric State
  getCipherState(): CipherState {
    return this.cs;
  }
}
