import debug from "debug";
import { proto_message } from "js-waku";
import { Decoder, Encoder, Message, ProtoMessage } from "js-waku/lib/interfaces";
import { MessageV0 } from "js-waku/lib/waku_message/version_0";

import { HandshakeResult, HandshakeStepResult } from "./handshake.js";
import { PayloadV2 } from "./payload.js";

const log = debug("waku:message:noise-encoder");

const OneMillion = BigInt(1_000_000);

export const Version = 2;

export class NoiseHandshakeEncoder implements Encoder {
  constructor(public contentTopic: string, private hsStepResult: HandshakeStepResult) {}

  async encode(message: Message): Promise<Uint8Array | undefined> {
    const protoMessage = await this.encodeProto(message);
    if (!protoMessage) return;
    return proto_message.WakuMessage.encode(protoMessage);
  }

  async encodeProto(message: Message): Promise<ProtoMessage | undefined> {
    const timestamp = message.timestamp ?? new Date();
    return {
      payload: this.hsStepResult.payload2.serialize(),
      version: Version,
      contentTopic: this.contentTopic,
      timestamp: BigInt(timestamp.valueOf()) * OneMillion,
    };
  }
}

export class NoiseHandshakeMessage extends MessageV0 implements Message {
  get payloadV2(): PayloadV2 {
    if (!this.payload) throw new Error("no payload available");
    return PayloadV2.deserialize(this.payload);
  }
}

export class NoiseSecureMessage extends MessageV0 implements Message {
  private readonly _decodedPayload: Uint8Array;

  constructor(proto: proto_message.WakuMessage, decodedPayload: Uint8Array) {
    super(proto);
    this._decodedPayload = decodedPayload;
  }

  get payload(): Uint8Array {
    return this._decodedPayload;
  }
}

export class NoiseHandshakeDecoder implements Decoder<NoiseHandshakeMessage> {
  constructor(public contentTopic: string) {}

  decodeProto(bytes: Uint8Array): Promise<ProtoMessage | undefined> {
    const protoMessage = proto_message.WakuMessage.decode(bytes);
    log("Message decoded", protoMessage);
    return Promise.resolve(protoMessage);
  }

  async decode(proto: ProtoMessage): Promise<NoiseHandshakeMessage | undefined> {
    // https://github.com/status-im/js-waku/issues/921
    if (proto.version === undefined) {
      proto.version = 0;
    }

    if (proto.version !== Version) {
      log("Failed to decode due to incorrect version, expected:", Version, ", actual:", proto.version);
      return Promise.resolve(undefined);
    }

    if (!proto.payload) {
      log("No payload, skipping: ", proto);
      return;
    }

    return new NoiseHandshakeMessage(proto);
  }
}

export class NoiseSecureTransferEncoder implements Encoder {
  constructor(public contentTopic: string, private hsResult: HandshakeResult) {}

  async encode(message: Message): Promise<Uint8Array | undefined> {
    const protoMessage = await this.encodeProto(message);
    if (!protoMessage) return;
    return proto_message.WakuMessage.encode(protoMessage);
  }

  async encodeProto(message: Message): Promise<ProtoMessage | undefined> {
    const timestamp = message.timestamp ?? new Date();
    if (!message.payload) {
      log("No payload to encrypt, skipping: ", message);
      return;
    }

    const preparedPayload = this.hsResult.writeMessage(message.payload);

    const payload = preparedPayload.serialize();

    return {
      payload,
      version: Version,
      contentTopic: this.contentTopic,
      timestamp: BigInt(timestamp.valueOf()) * OneMillion,
    };
  }
}

export class NoiseSecureTransferDecoder implements Decoder<NoiseSecureMessage> {
  constructor(public contentTopic: string, private hsResult: HandshakeResult) {}

  decodeProto(bytes: Uint8Array): Promise<ProtoMessage | undefined> {
    const protoMessage = proto_message.WakuMessage.decode(bytes);
    log("Message decoded", protoMessage);
    return Promise.resolve(protoMessage);
  }

  async decode(proto: ProtoMessage): Promise<NoiseSecureMessage | undefined> {
    // https://github.com/status-im/js-waku/issues/921
    if (proto.version === undefined) {
      proto.version = 0;
    }

    if (proto.version !== Version) {
      log("Failed to decode due to incorrect version, expected:", Version, ", actual:", proto.version);
      return Promise.resolve(undefined);
    }

    if (!proto.payload) {
      log("No payload, skipping: ", proto);
      return;
    }

    const payloadV2 = PayloadV2.deserialize(proto.payload);

    const decryptedPayload = this.hsResult.readMessage(payloadV2);

    return new NoiseSecureMessage(proto, decryptedPayload);
  }
}
