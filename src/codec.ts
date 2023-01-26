import debug from "debug";
import { proto_message } from "js-waku";
import { Decoder, Encoder, Message, ProtoMessage } from "js-waku/lib/interfaces";
import { MessageV0 } from "js-waku/lib/waku_message/version_0";

import { HandshakeResult, HandshakeStepResult } from "./handshake.js";
import { PayloadV2 } from "./payload.js";

const log = debug("waku:message:noise-codec");

const OneMillion = BigInt(1_000_000);

// WakuMessage version for noise protocol
const version = 2;

/**
 * Used internally in the pairing object to represent a handshake message
 */
export class NoiseHandshakeMessage extends MessageV0 implements Message {
  get payloadV2(): PayloadV2 {
    if (!this.payload) throw new Error("no payload available");
    return PayloadV2.deserialize(this.payload);
  }
}

/**
 * Used in the pairing object for encoding the messages exchanged
 * during the handshake process
 */
export class NoiseHandshakeEncoder implements Encoder {
  /**
   * @param contentTopic content topic on which the encoded WakuMessages will be sent
   * @param hsStepResult the result of a step executed while performing the handshake process
   */
  constructor(public contentTopic: string, private hsStepResult: HandshakeStepResult) {}

  async toWire(message: Partial<Message>): Promise<Uint8Array | undefined> {
    const protoMessage = await this.toProtoObj(message);
    if (!protoMessage) return;
    return proto_message.WakuMessage.encode(protoMessage);
  }

  async toProtoObj(message: Partial<Message>): Promise<ProtoMessage | undefined> {
    const timestamp = message.timestamp ?? new Date();
    return {
      rateLimitProof: undefined,
      payload: this.hsStepResult.payload2.serialize(),
      version: version,
      contentTopic: this.contentTopic,
      timestamp: BigInt(timestamp.valueOf()) * OneMillion,
    };
  }
}

/**
 * Used in the pairing object for decoding the messages exchanged
 * during the handshake process
 */
export class NoiseHandshakeDecoder implements Decoder<NoiseHandshakeMessage> {
  /**
   * @param contentTopic content topic on which the encoded WakuMessages were sent
   */
  constructor(public contentTopic: string) {}

  fromWireToProtoObj(bytes: Uint8Array): Promise<ProtoMessage | undefined> {
    const protoMessage = proto_message.WakuMessage.decode(bytes);
    log("Message decoded", protoMessage);
    // TODO(@weboko): remove type casting when released
    // https://github.com/waku-org/js-waku/pull/1136
    return Promise.resolve(protoMessage as ProtoMessage);
  }

  async fromProtoObj(proto: ProtoMessage): Promise<NoiseHandshakeMessage | undefined> {
    // https://github.com/status-im/js-waku/issues/921
    if (proto.version === undefined) {
      proto.version = 0;
    }

    if (proto.version !== version) {
      log("Failed to decode due to incorrect version, expected:", version, ", actual:", proto.version);
      return Promise.resolve(undefined);
    }

    if (!proto.payload) {
      log("No payload, skipping: ", proto);
      return;
    }

    return new NoiseHandshakeMessage(proto);
  }
}

/**
 * Represents a secure message. These are messages that are transmitted
 * after a successful handshake is performed.
 */
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

/**
 * js-waku encoder for secure messages. After a handshake is successful, a
 * codec for encoding messages is generated. The messages encoded with this
 * codec will be encrypted with the cipherstates and message nametags that were
 * created after a handshake is complete
 */
export class NoiseSecureTransferEncoder implements Encoder {
  /**
   * @param contentTopic content topic on which the encoded WakuMessages were sent
   * @param hsResult handshake result obtained after the handshake is successful
   */
  constructor(public contentTopic: string, private hsResult: HandshakeResult) {}

  async toWire(message: Partial<Message>): Promise<Uint8Array | undefined> {
    const protoMessage = await this.toProtoObj(message);
    if (!protoMessage) return;
    return proto_message.WakuMessage.encode(protoMessage);
  }

  async toProtoObj(message: Partial<Message>): Promise<ProtoMessage | undefined> {
    const timestamp = message.timestamp ?? new Date();
    if (!message.payload) {
      log("No payload to encrypt, skipping: ", message);
      return;
    }

    const preparedPayload = this.hsResult.writeMessage(message.payload);

    const payload = preparedPayload.serialize();

    return {
      payload,
      rateLimitProof: undefined,
      version: version,
      contentTopic: this.contentTopic,
      timestamp: BigInt(timestamp.valueOf()) * OneMillion,
    };
  }
}

/**
 * js-waku decoder for secure messages. After a handshake is successful, a codec
 * for decoding messages is generated. This decoder will attempt to decrypt
 * messages with the cipherstates and message nametags that were created after a
 * handshake is complete
 */
export class NoiseSecureTransferDecoder implements Decoder<NoiseSecureMessage> {
  /**
   * @param contentTopic content topic on which the encoded WakuMessages were sent
   * @param hsResult handshake result obtained after the handshake is successful
   */
  constructor(public contentTopic: string, private hsResult: HandshakeResult) {}

  fromWireToProtoObj(bytes: Uint8Array): Promise<ProtoMessage | undefined> {
    const protoMessage = proto_message.WakuMessage.decode(bytes);
    log("Message decoded", protoMessage);
    // TODO(@weboko): remove type casting when released
    // https://github.com/waku-org/js-waku/pull/1136
    return Promise.resolve(protoMessage as ProtoMessage);
  }

  async fromProtoObj(proto: ProtoMessage): Promise<NoiseSecureMessage | undefined> {
    // https://github.com/status-im/js-waku/issues/921
    if (proto.version === undefined) {
      proto.version = 0;
    }

    if (proto.version !== version) {
      log("Failed to decode due to incorrect version, expected:", version, ", actual:", proto.version);
      return Promise.resolve(undefined);
    }

    if (!proto.payload) {
      log("No payload, skipping: ", proto);
      return;
    }

    try {
      const payloadV2 = PayloadV2.deserialize(proto.payload);
      const decryptedPayload = this.hsResult.readMessage(payloadV2);
      return new NoiseSecureMessage(proto, decryptedPayload);
    } catch (err) {
      log("could not decode message ", err);
      return;
    }
  }
}
