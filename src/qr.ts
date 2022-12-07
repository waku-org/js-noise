import { decode, encode, fromUint8Array, toUint8Array } from "js-base64";

import { bytes32 } from "./@types/basic.js";

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
    let qr = encode(this.applicationName) + ":";
    qr += encode(this.applicationVersion) + ":";
    qr += encode(this.shardId) + ":";
    qr += fromUint8Array(this.ephemeralKey) + ":";
    qr += fromUint8Array(this.committedStaticKey);

    return qr;
  }

  toByteArray(): Uint8Array {
    const enc = new TextEncoder();
    return enc.encode(this.toString());
  }

  // Deserializes input string in base64 to the corresponding (applicationName, applicationVersion, shardId, ephemeralKey, committedStaticKey)
  static fromString(qrString: string): QR {
    const values = qrString.split(":");

    if (values.length != 5) throw new Error("invalid qr string");

    const applicationName = decode(values[0]);
    const applicationVersion = decode(values[1]);
    const shardId = decode(values[2]);
    const ephemeralKey = toUint8Array(values[3]);
    const committedStaticKey = toUint8Array(values[4]);

    return new QR(applicationName, applicationVersion, shardId, ephemeralKey, committedStaticKey);
  }
}
