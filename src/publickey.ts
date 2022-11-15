import { equals as uint8ArrayEquals } from "uint8arrays/equals";

import { bytes32 } from "./@types/basic";

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
  static to(publicKey: bytes32): NoisePublicKey {
    return new NoisePublicKey(0, publicKey);
  }
}
