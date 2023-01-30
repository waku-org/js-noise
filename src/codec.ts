import debug from "debug";
import { DecodedMessage, Decoder, Encoder, proto } from "@waku/core/lib/message/version_0";

import { HandshakeResult, HandshakeStepResult } from "./handshake.js";
import { PayloadV2 } from "./payload.js";

const log = debug("waku:message:noise-codec");

// WakuMessage version for noise protocol
const version = 2;

/**
 * Used internally in the pairing object to represent a handshake message
 */
export class NoiseHandshakeMessage extends DecodedMessage {
  get payloadV2(): PayloadV2 {
    if (!this.payload) throw new Error("no payload available");
    return PayloadV2.deserialize(this.payload);
  }
}

/**
 * Used in the pairing object for encoding the messages exchanged
 * during the handshake process
 */
export class NoiseHandshakeEncoder extends Encoder {
  /**
   * @param contentTopic content topic on which the encoded WakuMessages will be sent
   * @param hsStepResult the result of a step executed while performing the handshake process
   */
  constructor(public contentTopic: string, private hsStepResult: HandshakeStepResult) {
    super(contentTopic);
  }
}

/**
 * Used in the pairing object for decoding the messages exchanged
 * during the handshake process
 */
export class NoiseHandshakeDecoder extends Decoder {
  /**
   * @param contentTopic content topic on which the encoded WakuMessages were sent
   */
  constructor(public contentTopic: string) {
    super(contentTopic);
  }

  async fromProtoObj(proto: proto.WakuMessage): Promise<NoiseHandshakeMessage | undefined> {
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
export class NoiseSecureMessage extends DecodedMessage {}

/**
 * js-waku encoder for secure messages. After a handshake is successful, a
 * codec for encoding messages is generated. The messages encoded with this
 * codec will be encrypted with the cipherstates and message nametags that were
 * created after a handshake is complete
 */
export class NoiseSecureTransferEncoder extends Encoder {
  /**
   * @param contentTopic content topic on which the encoded WakuMessages were sent
   * @param hsResult handshake result obtained after the handshake is successful
   */
  constructor(public contentTopic: string, private hsResult: HandshakeResult) {
    super(contentTopic);
  }
}

/**
 * js-waku decoder for secure messages. After a handshake is successful, a codec
 * for decoding messages is generated. This decoder will attempt to decrypt
 * messages with the cipherstates and message nametags that were created after a
 * handshake is complete
 */
export class NoiseSecureTransferDecoder extends Decoder {
  /**
   * @param contentTopic content topic on which the encoded WakuMessages were sent
   * @param hsResult handshake result obtained after the handshake is successful
   */
  constructor(public contentTopic: string, private hsResult: HandshakeResult) {
    super(contentTopic);
  }

  async fromProtoObj(proto: proto.WakuMessage): Promise<NoiseSecureMessage | undefined> {
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
      return new NoiseSecureMessage(proto);
    } catch (err) {
      log("could not decode message ", err);
      return;
    }
  }
}
