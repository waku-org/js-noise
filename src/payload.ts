// PayloadV2 defines an object for Waku payloads with version 2 as in
// https://rfc.vac.dev/spec/35/#public-keys-serialization
// It contains a message nametag, protocol ID field, the handshake message (for Noise handshakes) and

import { concat as uint8ArrayConcat } from "uint8arrays/concat";
import { equals as uint8ArrayEquals } from "uint8arrays/equals";

import { MessageNametag } from "./@types/handshake";
import { ChachaPolyTagLen, Curve25519KeySize, hashSHA256 } from "./crypto";
import { PayloadV2ProtocolIDs } from "./patterns";
import { NoisePublicKey } from "./publickey";
import { readUIntLE, writeUIntLE } from "./utils";

export const MessageNametagLength = 16;
export const MessageNametagBufferSize = 50;

// Converts a sequence or array (arbitrary size) to a MessageNametag
export function toMessageNametag(input: Uint8Array): MessageNametag {
  return input.subarray(0, MessageNametagLength);
}

export class MessageNametagBuffer {
  private buffer: Array<MessageNametag> = new Array<MessageNametag>(MessageNametagBufferSize);
  private counter = 0;
  secret?: Uint8Array;

  constructor() {
    for (let i = 0; i < this.buffer.length; i++) {
      this.buffer[i] = new Uint8Array(MessageNametagLength);
    }
  }

  // Initializes the empty Message nametag buffer. The n-th nametag is equal to HKDF( secret || n )
  initNametagsBuffer(): void {
    // We default the counter and buffer fields
    this.counter = 0;
    this.buffer = new Array<MessageNametag>(MessageNametagBufferSize);

    if (this.secret) {
      for (let i = 0; i < this.buffer.length; i++) {
        const counterBytesLE = writeUIntLE(new Uint8Array(8), this.counter, 0, 8);
        const d = hashSHA256(uint8ArrayConcat([this.secret, counterBytesLE]));
        this.buffer[i] = toMessageNametag(d);
        this.counter++;
      }
    } else {
      // We warn users if no secret is set
      console.debug("The message nametags buffer has not a secret set");
    }
  }

  pop(): MessageNametag {
    // Note that if the input MessageNametagBuffer is set to default, an all 0 messageNametag is returned
    const messageNametag = new Uint8Array(this.buffer[0]);
    this.delete(1);
    return messageNametag;
  }

  // Checks if the input messageNametag is contained in the input MessageNametagBuffer
  checkNametag(messageNametag: MessageNametag): boolean {
    const index = this.buffer.findIndex((x) => uint8ArrayEquals(x, messageNametag));

    if (index == -1) {
      console.error("Message nametag not found in buffer");
      return false;
    } else if (index > 0) {
      console.error(
        "Message nametag is present in buffer but is not the next expected nametag. One or more messages were probably lost"
      );
      return false;
    }

    // index is 0, hence the read message tag is the next expected one
    return true;
  }

  // Deletes the first n elements in buffer and appends n new ones
  delete(n: number): void {
    if (n <= 0) {
      return;
    }

    // We ensure n is at most MessageNametagBufferSize (the buffer will be fully replaced)
    n = Math.min(n, MessageNametagBufferSize);

    // We update the last n values in the array if a secret is set
    // Note that if the input MessageNametagBuffer is set to default, nothing is done here
    if (this.secret) {
      // We rotate left the array by n
      for (let i = 0; i < n; i++) {
        const first = this.buffer.shift();
        if (first) this.buffer.push(first);
      }

      for (let i = 0; i < n; i++) {
        const counterBytesLE = writeUIntLE(new Uint8Array(8), this.counter, 0, 8);
        const d = hashSHA256(uint8ArrayConcat([this.secret, counterBytesLE]));

        this.buffer[this.buffer.length - n + i] = toMessageNametag(d);
        this.counter++;
      }
    } else {
      // We warn users that no secret is set
      console.debug("The message nametags buffer has no secret set");
    }
  }
}

export class PayloadV2 {
  messageNametag: MessageNametag;
  protocolId: number;
  handshakeMessage: Array<NoisePublicKey>;
  transportMessage: Uint8Array;

  constructor(
    messageNametag: MessageNametag = new Uint8Array(MessageNametagLength),
    protocolId = 0,
    handshakeMessage: Array<NoisePublicKey> = [],
    transportMessage: Uint8Array = new Uint8Array()
  ) {
    this.messageNametag = messageNametag;
    this.protocolId = protocolId;
    this.handshakeMessage = handshakeMessage;
    this.transportMessage = transportMessage;
  }

  clone(): PayloadV2 {
    const r = new PayloadV2();
    r.protocolId = this.protocolId;
    r.transportMessage = new Uint8Array(this.transportMessage);
    r.messageNametag = new Uint8Array(this.messageNametag);
    for (let i = 0; i < this.handshakeMessage.length; i++) {
      r.handshakeMessage.push(this.handshakeMessage[i].clone());
    }
    return r;
  }

  equals(b: PayloadV2): boolean {
    let pkEquals = true;
    if (this.handshakeMessage.length != b.handshakeMessage.length) {
      pkEquals = false;
    }

    for (let i = 0; i < this.handshakeMessage.length; i++) {
      if (!this.handshakeMessage[i].equals(b.handshakeMessage[i])) {
        pkEquals = false;
        break;
      }
    }

    return (
      uint8ArrayEquals(this.messageNametag, b.messageNametag) &&
      this.protocolId == b.protocolId &&
      uint8ArrayEquals(this.transportMessage, b.transportMessage) &&
      pkEquals
    );
  }

  // Serializes a PayloadV2 object to a byte sequences according to https://rfc.vac.dev/spec/35/.
  // The output serialized payload concatenates the input PayloadV2 object fields as
  // payload = ( protocolId || serializedHandshakeMessageLen || serializedHandshakeMessage || transportMessageLen || transportMessage)
  // The output can be then passed to the payload field of a WakuMessage https://rfc.vac.dev/spec/14/
  serialize(): Uint8Array {
    // We collect public keys contained in the handshake message

    // According to https://rfc.vac.dev/spec/35/, the maximum size for the handshake message is 256 bytes, that is
    // the handshake message length can be represented with 1 byte only. (its length can be stored in 1 byte)
    // However, to ease public keys length addition operation, we declare it as int and later cast to uit8
    let serializedHandshakeMessageLen = 0;
    // This variables will store the concatenation of the serializations of all public keys in the handshake message
    let serializedHandshakeMessage = new Uint8Array();

    // For each public key in the handshake message
    for (const pk of this.handshakeMessage) {
      // We serialize the public key
      const serializedPk = pk.serialize();
      // We sum its serialized length to the total
      serializedHandshakeMessageLen += serializedPk.length;
      // We add its serialization to the concatenation of all serialized public keys in the handshake message
      serializedHandshakeMessage = uint8ArrayConcat([serializedHandshakeMessage, serializedPk]);
      // If we are processing more than 256 byte, we return an error
      if (serializedHandshakeMessageLen > 255) {
        console.debug("PayloadV2 malformed: too many public keys contained in the handshake message");
        throw new Error("too many public keys in handshake message");
      }
    }

    // The output payload as in https://rfc.vac.dev/spec/35/. We concatenate all the PayloadV2 fields as
    // payload = ( protocolId || serializedHandshakeMessageLen || serializedHandshakeMessage || transportMessageLen || transportMessage)

    // We concatenate all the data
    // The protocol ID (1 byte) and handshake message length (1 byte) can be directly casted to byte to allow direct copy to the payload byte sequence
    const payload = uint8ArrayConcat([
      this.messageNametag,
      new Uint8Array([this.protocolId]),
      new Uint8Array([serializedHandshakeMessageLen]),
      serializedHandshakeMessage,
      // The transport message length is converted from uint64 to bytes in Little-Endian
      writeUIntLE(new Uint8Array(8), this.transportMessage.length, 0, 8),
      this.transportMessage,
    ]);

    return payload;
  }

  // Deserializes a byte sequence to a PayloadV2 object according to https://rfc.vac.dev/spec/35/.
  // The input serialized payload concatenates the output PayloadV2 object fields as
  // payload = ( messageNametag || protocolId || serializedHandshakeMessageLen || serializedHandshakeMessage || transportMessageLen || transportMessage)
  static deserialize(payload: Uint8Array): PayloadV2 {
    // i is the read input buffer position index
    let i = 0;

    // We start by reading the messageNametag
    const messageNametag = new Uint8Array(MessageNametagLength);
    for (let j = 0; j < MessageNametagLength; j++) {
      messageNametag[j] = payload[i + j];
    }
    i += MessageNametagLength;

    // We read the Protocol ID
    const protocolId = payload[i];
    const protocolName = Object.keys(PayloadV2ProtocolIDs).find((key) => PayloadV2ProtocolIDs[key] === protocolId);
    if (protocolName === undefined) {
      throw new Error("protocolId not found");
    }

    i++;

    // We read the Handshake Message length (1 byte)
    const handshakeMessageLen = payload[i];
    if (handshakeMessageLen > 255) {
      console.debug("payload malformed: too many public keys contained in the handshake message");
      throw new Error("too many public keys in handshake message");
    }

    i++;

    // We now read for handshakeMessageLen bytes the buffer and we deserialize each (encrypted/unencrypted) public key read
    // In handshakeMessage we accumulate the read deserialized Noise Public keys
    const handshakeMessage = new Array<NoisePublicKey>();
    let written = 0;

    // We read the buffer until handshakeMessageLen are read
    while (written != handshakeMessageLen) {
      // We obtain the current Noise Public key encryption flag
      const flag = payload[i];
      // If the key is unencrypted, we only read the X coordinate of the EC public key and we deserialize into a Noise Public Key
      if (flag === 0) {
        const pkLen = 1 + Curve25519KeySize;
        handshakeMessage.push(NoisePublicKey.deserialize(payload.subarray(i, i + pkLen)));
        i += pkLen;
        written += pkLen;
        // If the key is encrypted, we only read the encrypted X coordinate and the authorization tag, and we deserialize into a Noise Public Key
      } else if (flag === 1) {
        const pkLen = 1 + Curve25519KeySize + ChachaPolyTagLen;
        handshakeMessage.push(NoisePublicKey.deserialize(payload.subarray(i, i + pkLen)));
        i += pkLen;
        written += pkLen;
      } else {
        throw new Error("invalid flag for Noise public key");
      }
    }

    // We read the transport message length (8 bytes) and we convert to uint64 in Little Endian
    const transportMessageLen = readUIntLE(payload, i, i + 8 - 1);
    i += 8;

    // We read the transport message (handshakeMessage bytes)
    const transportMessage = payload.subarray(i, i + transportMessageLen);
    i += transportMessageLen;

    return new PayloadV2(messageNametag, protocolId, handshakeMessage, transportMessage);
  }
}
