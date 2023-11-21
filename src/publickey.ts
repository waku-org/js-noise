import { concat as uint8ArrayConcat } from "uint8arrays/concat";
import { equals as uint8ArrayEquals } from "uint8arrays/equals";

import { bytes32 } from "./@types/basic.js";

/**
 * A Noise public key is a public key exchanged during Noise handshakes (no private part)
 * This follows https://rfc.vac.dev/spec/35/#public-keys-serialization
 */
export class NoisePublicKey {
  /**
   * @param flag 1 to indicate that the public key is encrypted, 0 for unencrypted.
   * Note: besides encryption, flag can be used to distinguish among multiple supported Elliptic Curves
   * @param pk contains the X coordinate of the public key, if unencrypted
   * or the encryption of the X coordinate concatenated with the authorization tag, if encrypted
   */
  constructor(public readonly flag: number, public readonly pk: Uint8Array) {}

  /**
   * Create a copy of the NoisePublicKey
   * @returns a copy of the NoisePublicKey
   */
  clone(): NoisePublicKey {
    return new NoisePublicKey(this.flag, new Uint8Array(this.pk));
  }

  /**
   * Check NoisePublicKey equality
   * @param other object to compare against
   * @returns true if equal, false otherwise
   */
  equals(other: NoisePublicKey): boolean {
    return this.flag == other.flag && uint8ArrayEquals(this.pk, other.pk);
  }

  /**
   * Converts a public Elliptic Curve key to an unencrypted Noise public key
   * @param publicKey 32-byte public key
   * @returns NoisePublicKey
   */
  static fromPublicKey(publicKey: bytes32): NoisePublicKey {
    return new NoisePublicKey(0, publicKey);
  }

  /**
   * Converts a Noise public key to a stream of bytes as in https://rfc.vac.dev/spec/35/#public-keys-serialization
   * @returns Serialized NoisePublicKey
   */
  serialize(): Uint8Array {
    // Public key is serialized as (flag || pk)
    // Note that pk contains the X coordinate of the public key if unencrypted
    // or the encryption concatenated with the authorization tag if encrypted
    const serializedNoisePublicKey = new Uint8Array(uint8ArrayConcat([new Uint8Array([this.flag ? 1 : 0]), this.pk]));
    return serializedNoisePublicKey;
  }

  /**
   * Converts a serialized Noise public key to a NoisePublicKey object as in https://rfc.vac.dev/spec/35/#public-keys-serialization
   * @param serializedPK Serialized NoisePublicKey
   * @returns NoisePublicKey
   */
  static deserialize(serializedPK: Uint8Array): NoisePublicKey {
    if (serializedPK.length == 0) throw new Error("invalid serialized key");

    // We retrieve the encryption flag
    const flag = serializedPK[0];
    if (!(flag == 0 || flag == 1)) throw new Error("invalid flag in serialized public key");

    const pk = serializedPK.subarray(1);

    return new NoisePublicKey(flag, pk);
  }
}
