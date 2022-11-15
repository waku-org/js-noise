// PayloadV2 defines an object for Waku payloads with version 2 as in
// https://rfc.vac.dev/spec/35/#public-keys-serialization
// It contains a message nametag, protocol ID field, the handshake message (for Noise handshakes) and

import { concat as uint8ArrayConcat } from "uint8arrays/concat";
import { equals as uint8ArrayEquals } from "uint8arrays/equals";

import { MessageNametag } from "./@types/handshake";
import { hashSHA256 } from "./crypto";
import { NoisePublicKey } from "./publickey";

const MessageNametagLength = 16;
const MessageNametagBufferSize = 50;

// Converts a sequence or array (arbitrary size) to a MessageNametag
export function toMessageNametag(input: Uint8Array): MessageNametag {
  return input.subarray(0, MessageNametagLength);
}

// Adapted from https://github.com/feross/buffer

function checkInt(buf: Uint8Array, value: number, offset: number, ext: number, max: number, min: number): void {
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds');
  if (offset + ext > buf.length) throw new RangeError("Index out of range");
}

const writeUIntLE = function writeUIntLE(
  buf: Uint8Array,
  value: number,
  offset: number,
  byteLength: number,
  noAssert?: boolean
): Uint8Array {
  value = +value;
  offset = offset >>> 0;
  byteLength = byteLength >>> 0;
  if (!noAssert) {
    const maxBytes = Math.pow(2, 8 * byteLength) - 1;
    checkInt(buf, value, offset, byteLength, maxBytes, 0);
  }

  let mul = 1;
  let i = 0;
  buf[offset] = value & 0xff;
  while (++i < byteLength && (mul *= 0x100)) {
    buf[offset + i] = (value / mul) & 0xff;
  }

  return buf;
};

export class MessageNametagBuffer {
  buffer: Array<MessageNametag> = new Array<MessageNametag>(MessageNametagBufferSize);
  counter = 0;
  secret?: Uint8Array;

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
    const messageNametag = this.buffer[0];
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
        const first = this.buffer.shift()!;
        this.buffer.push(first);
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
}
