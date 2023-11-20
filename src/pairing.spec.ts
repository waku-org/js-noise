import { HMACDRBG } from "@stablelib/hmac-drbg";
import { randomBytes } from "@stablelib/random";
import type { IDecoder, IEncoder, IMessage, IProtoMessage, IReceiver, ISender } from "@waku/interfaces";
import { expect } from "chai";
import { EventEmitter } from "eventemitter3";
import { pEvent } from "p-event";
import { equals as uint8ArrayEquals } from "uint8arrays/equals";

import { NoiseHandshakeMessage } from "./codec";
import { DH25519 } from "./dh25519";
import { MessageNametagBufferSize } from "./messagenametag";
import { ResponderParameters, WakuPairing } from "./pairing";

const PUBSUB_TOPIC = "default";

const EMPTY_PROTOMESSAGE = {
  timestamp: undefined,
  contentTopic: "",
  ephemeral: undefined,
  meta: undefined,
  rateLimitProof: undefined,
  version: undefined,
};

describe("js-noise: pairing object", () => {
  const rng = new HMACDRBG();

  const confirmAuthCodeFlow = async function (pairingObj: WakuPairing, shouldConfirm: boolean): Promise<void> {
    const authCode = await pairingObj.getAuthCode();
    console.log("Authcode: ", authCode); // TODO: compare that authCode is the same in both confirmation flows
    pairingObj.validateAuthCode(shouldConfirm);
  };

  // =================
  // Simulate waku. This code is not meant to be used IRL
  const msgEmitter = new EventEmitter();
  const sender: ISender = {
    async send(encoder: IEncoder, msg: IMessage) {
      const protoMsg = await encoder.toProtoObj(msg);
      msgEmitter.emit(encoder.contentTopic, protoMsg);
      return {
        recipients: [],
      };
    },
  };
  const responder = {
    toSubscriptionIterator(decoder: IDecoder<NoiseHandshakeMessage>) {
      return {
        iterator: {
          async next() {
            const msg = await pEvent(msgEmitter, decoder.contentTopic);
            const decodedMessage = await decoder.fromProtoObj(PUBSUB_TOPIC, msg);
            return {
              value: decodedMessage,
              done: false,
            };
          },
        },
        stop() {
          // Do nothing. This is just a simulation
          console.debug("stopping subscription to", decoder.contentTopic);
        },
      };
    },
  } as any as IReceiver;
  // =================

  it("should pair", async function () {
    const dhKey = new DH25519();

    const bobStaticKey = dhKey.generateKeyPair();
    const aliceStaticKey = dhKey.generateKeyPair();

    const recvParameters = new ResponderParameters();
    const bobPairingObj = new WakuPairing(sender, responder, bobStaticKey, recvParameters);
    const bobExecP1 = bobPairingObj.execute();

    // Confirmation is done by manually
    confirmAuthCodeFlow(bobPairingObj, true);

    const initParameters = bobPairingObj.getPairingInfo();
    const alicePairingObj = new WakuPairing(sender, responder, aliceStaticKey, initParameters);
    const aliceExecP1 = alicePairingObj.execute();

    // Confirmation is done manually
    confirmAuthCodeFlow(alicePairingObj, true);

    const [bobCodecs, aliceCodecs] = await Promise.all([bobExecP1, aliceExecP1]);

    const bobEncoder = bobCodecs[0];
    const bobDecoder = bobCodecs[1];
    const aliceEncoder = aliceCodecs[0];
    const aliceDecoder = aliceCodecs[1];

    // We test read/write of random messages exchanged between Alice and Bob
    // Note that we exchange more than the number of messages contained in the nametag buffer to test if they are filled correctly as the communication proceeds
    for (let i = 0; i < 10 * MessageNametagBufferSize; i++) {
      // Alice writes to Bob
      let message = randomBytes(32, rng);
      let encodedMsg = await aliceEncoder.toWire({ payload: message });
      let readMessageProto = await bobDecoder.fromWireToProtoObj(encodedMsg!);
      let readMessage = await bobDecoder.fromProtoObj(PUBSUB_TOPIC, readMessageProto!);

      expect(uint8ArrayEquals(message, readMessage!.payload)).to.be.true;

      // Bob writes to Alice
      message = randomBytes(32, rng);
      encodedMsg = await bobEncoder.toWire({ payload: message });
      readMessageProto = await aliceDecoder.fromWireToProtoObj(encodedMsg!);
      readMessage = await aliceDecoder.fromProtoObj(PUBSUB_TOPIC, readMessageProto!);

      expect(uint8ArrayEquals(message, readMessage!.payload)).to.be.true;
    }
  });

  it("should timeout", async function () {
    const dhKey = new DH25519();
    const bobPairingObj = new WakuPairing(sender, responder, dhKey.generateKeyPair(), new ResponderParameters());
    const alicePairingObj = new WakuPairing(sender, responder, dhKey.generateKeyPair(), bobPairingObj.getPairingInfo());

    const bobExecP1 = bobPairingObj.execute(1000);
    const aliceExecP1 = alicePairingObj.execute(1000);

    try {
      await Promise.all([bobExecP1, aliceExecP1]);
      expect(false, "should not reach here").to.be.true;
    } catch (err) {
      let message;
      if (err instanceof Error) message = err.message;
      else message = String(err);
      expect(message).to.be.equals("pairing has timed out");
    }
  });

  it("pairs and `meta` field is encoded", async function () {
    const dhKey = new DH25519();
    const bobStaticKey = dhKey.generateKeyPair();
    const aliceStaticKey = dhKey.generateKeyPair();

    // Encode the length of the payload
    // Not a relevant real life example
    const metaSetter = (msg: IProtoMessage & { meta: undefined }): Uint8Array => {
      const buffer = new ArrayBuffer(4);
      const view = new DataView(buffer);
      view.setUint32(0, msg.payload.length, false);
      return new Uint8Array(buffer);
    };

    const recvParameters = new ResponderParameters();
    const bobPairingObj = new WakuPairing(sender, responder, bobStaticKey, recvParameters, undefined, { metaSetter });
    const bobExecP1 = bobPairingObj.execute();

    // Confirmation is done by manually
    confirmAuthCodeFlow(bobPairingObj, true);

    const initParameters = bobPairingObj.getPairingInfo();
    const alicePairingObj = new WakuPairing(sender, responder, aliceStaticKey, initParameters, undefined, {
      metaSetter,
    });
    const aliceExecP1 = alicePairingObj.execute();

    // Confirmation is done manually
    confirmAuthCodeFlow(alicePairingObj, true);

    const [bobCodecs, aliceCodecs] = await Promise.all([bobExecP1, aliceExecP1]);

    const bobEncoder = bobCodecs[0];
    const bobDecoder = bobCodecs[1];
    const aliceEncoder = aliceCodecs[0];
    const aliceDecoder = aliceCodecs[1];

    // We test read/write of random messages exchanged between Alice and Bob
    // Note that we exchange more than the number of messages contained in the nametag buffer to test if they are filled correctly as the communication proceeds
    for (let i = 0; i < 10 * MessageNametagBufferSize; i++) {
      // Alice writes to Bob
      let message = randomBytes(32, rng);
      let encodedMsg = await aliceEncoder.toWire({ payload: message });
      let readMessageProto = await bobDecoder.fromWireToProtoObj(encodedMsg!);
      let readMessage = await bobDecoder.fromProtoObj(PUBSUB_TOPIC, readMessageProto!);

      expect(uint8ArrayEquals(message, readMessage!.payload)).to.be.true;

      let expectedMeta = metaSetter({
        ...EMPTY_PROTOMESSAGE,
        payload: readMessageProto!.payload,
      });

      expect(readMessage!.meta).to.deep.eq(expectedMeta);

      // Bob writes to Alice
      message = randomBytes(32, rng);
      encodedMsg = await bobEncoder.toWire({ payload: message });
      readMessageProto = await aliceDecoder.fromWireToProtoObj(encodedMsg!);
      readMessage = await aliceDecoder.fromProtoObj(PUBSUB_TOPIC, readMessageProto!);

      expect(uint8ArrayEquals(message, readMessage!.payload)).to.be.true;

      expectedMeta = metaSetter({
        ...EMPTY_PROTOMESSAGE,
        payload: readMessageProto!.payload,
      });

      expect(readMessage!.meta).to.deep.eq(expectedMeta);
    }
  });
});
