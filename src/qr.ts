import { fromString, toString } from "uint8arrays";

import { bytes32 } from "./@types/basic.js";

/**
 * QR code generation
 */
export class QR {
  constructor(
    public readonly applicationName: string,
    public readonly applicationVersion: string,
    public readonly shardId: string,
    public readonly ephemeralKey: bytes32,
    public readonly committedStaticKey: bytes32
  ) {}

  // Serializes input parameters to a base64 string for exposure through QR code (used by WakuPairing)
  toString(): string {
    let qr = toString(fromString(this.applicationName), "base64urlpad") + ":";
    qr += toString(fromString(this.applicationVersion), "base64urlpad") + ":";
    qr += toString(fromString(this.shardId), "base64urlpad") + ":";
    qr += toString(this.ephemeralKey, "base64urlpad") + ":";
    qr += toString(this.committedStaticKey, "base64urlpad");

    return qr;
  }

  /**
   * Convert QR code into byte array
   * @returns byte array serialization of a base64 encoded QR code
   */
  toByteArray(): Uint8Array {
    const enc = new TextEncoder();
    return enc.encode(this.toString());
  }

  /**
   * Deserializes input string in base64 to the corresponding (applicationName, applicationVersion, shardId, ephemeralKey, committedStaticKey)
   * @param input input base64 encoded string
   * @returns QR
   */
  static from(input: string | Uint8Array): QR {
    let qrStr: string;
    if (input instanceof Uint8Array) {
      const dec = new TextDecoder();
      qrStr = dec.decode(input);
    } else {
      qrStr = input;
    }

    const values = qrStr.split(":");

    if (values.length != 5) throw new Error("invalid qr string");

    const applicationName = toString(fromString(values[0], "base64urlpad"));
    const applicationVersion = toString(fromString(values[1], "base64urlpad"));
    const shardId = toString(fromString(values[2], "base64urlpad"));
    const ephemeralKey = fromString(values[3], "base64urlpad");
    const committedStaticKey = fromString(values[4], "base64urlpad");

    return new QR(applicationName, applicationVersion, shardId, ephemeralKey, committedStaticKey);
  }
}
