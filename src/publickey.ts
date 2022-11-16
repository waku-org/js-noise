import { concat as uint8ArrayConcat } from "uint8arrays/concat";
import { equals as uint8ArrayEquals } from "uint8arrays/equals";

import { bytes32 } from "./@types/basic";
import { chaCha20Poly1305Decrypt, chaCha20Poly1305Encrypt } from "./crypto";
import { isEmptyKey } from "./noise";

// A ChaChaPoly Cipher State containing key (k), nonce (nonce) and associated data (ad)
export class ChaChaPolyCipherState {
  k: bytes32;
  nonce: bytes32;
  ad: Uint8Array;
  constructor(k: bytes32 = new Uint8Array(), nonce: bytes32 = new Uint8Array(), ad: Uint8Array = new Uint8Array()) {
    this.k = k;
    this.nonce = nonce;
    this.ad = ad;
  }

  // It takes a Cipher State (with key, nonce, and associated data) and encrypts a plaintext
  // The cipher state in not changed
  encrypt(plaintext: Uint8Array): Uint8Array {
    // If plaintext is empty, we raise an error
    if (plaintext.length == 0) {
      throw new Error("tried to encrypt empty plaintext");
    }

    return chaCha20Poly1305Encrypt(plaintext, this.nonce, this.ad, this.k);
  }

  // ChaChaPoly decryption
  // It takes a Cipher State (with key, nonce, and associated data) and decrypts a ciphertext
  // The cipher state is not changed
  decrypt(ciphertext: Uint8Array): Uint8Array {
    // If ciphertext is empty, we raise an error
    if (ciphertext.length == 0) {
      throw new Error("tried to decrypt empty ciphertext");
    }
    const plaintext = chaCha20Poly1305Decrypt(ciphertext, this.nonce, this.ad, this.k);
    if (!plaintext) {
      throw new Error("decryptWithAd failed");
    }

    return plaintext;
  }
}

// A Noise public key is a public key exchanged during Noise handshakes (no private part)
// This follows https://rfc.vac.dev/spec/35/#public-keys-serialization
// pk contains the X coordinate of the public key, if unencrypted (this implies flag = 0)
// or the encryption of the X coordinate concatenated with the authorization tag, if encrypted (this implies flag = 1)
// Note: besides encryption, flag can be used to distinguish among multiple supported Elliptic Curves
export class NoisePublicKey {
  flag: number;
  pk: Uint8Array;

  constructor(flag: number, pk: Uint8Array) {
    this.flag = flag;
    this.pk = pk;
  }

  clone(): NoisePublicKey {
    return new NoisePublicKey(this.flag, new Uint8Array(this.pk));
  }

  // Checks equality between two Noise public keys
  equals(k2: NoisePublicKey): boolean {
    return this.flag == k2.flag && uint8ArrayEquals(this.pk, k2.pk);
  }

  // Converts a public Elliptic Curve key to an unencrypted Noise public key
  static fromPublicKey(publicKey: bytes32): NoisePublicKey {
    return new NoisePublicKey(0, publicKey);
  }

  // Converts a Noise public key to a stream of bytes as in
  // https://rfc.vac.dev/spec/35/#public-keys-serialization
  serialize(): Uint8Array {
    // Public key is serialized as (flag || pk)
    // Note that pk contains the X coordinate of the public key if unencrypted
    // or the encryption concatenated with the authorization tag if encrypted
    const serializedNoisePublicKey = new Uint8Array(uint8ArrayConcat([new Uint8Array([this.flag ? 1 : 0]), this.pk]));
    return serializedNoisePublicKey;
  }

  // Converts a serialized Noise public key to a NoisePublicKey object as in
  // https://rfc.vac.dev/spec/35/#public-keys-serialization
  static deserialize(serializedPK: Uint8Array): NoisePublicKey {
    if (serializedPK.length == 0) throw new Error("invalid serialized key");

    // We retrieve the encryption flag
    const flag = serializedPK[0];
    if (!(flag == 0 || flag == 1)) throw new Error("invalid flag in serialized public key");

    const pk = serializedPK.subarray(1);

    return new NoisePublicKey(flag, pk);
  }

  static encrypt(ns: NoisePublicKey, cs: ChaChaPolyCipherState): NoisePublicKey {
    // We proceed with encryption only if
    // - a key is set in the cipher state
    // - the public key is unencrypted
    if (!isEmptyKey(cs.k) && ns.flag == 0) {
      const encPk = cs.encrypt(ns.pk);
      return new NoisePublicKey(1, encPk);
    }

    // Otherwise we return the public key as it is
    return ns.clone();
  }

  // Decrypts a Noise public key using a ChaChaPoly Cipher State
  static decrypt(ns: NoisePublicKey, cs: ChaChaPolyCipherState): NoisePublicKey {
    // We proceed with decryption only if
    // - a key is set in the cipher state
    // - the public key is encrypted
    if (!isEmptyKey(cs.k) && ns.flag == 1) {
      const decrypted = cs.decrypt(ns.pk);
      return new NoisePublicKey(0, decrypted);
    }

    // Otherwise we return the public key as it is
    return ns.clone();
  }
}
