import { HMACDRBG } from "@stablelib/hmac-drbg";
import { randomBytes } from "@stablelib/random";
import { expect } from "chai";
import { equals as uint8ArrayEquals } from "uint8arrays/equals";

import {
  NoiseHandshakeDecoder,
  NoiseHandshakeEncoder,
  NoiseSecureTransferDecoder,
  NoiseSecureTransferEncoder,
} from "./codec";
import { commitPublicKey, generateX25519KeyPair } from "./crypto";
import { Handshake } from "./handshake";
import { NoiseHandshakePatterns } from "./patterns";
import { MessageNametagBufferSize, MessageNametagLength } from "./payload";
import { NoisePublicKey } from "./publickey";
import { fromQr, toQr } from "./utils";

describe("Waku Noise Sessions", () => {
  const rng = new HMACDRBG();

  // This test implements the Device pairing and Secure Transfers with Noise
  // detailed in the 43/WAKU2-DEVICE-PAIRING RFC https://rfc.vac.dev/spec/43/
  it("Noise Waku Pairing Handhshake and Secure transfer", async function () {
    // Pairing Phase
    // ==========

    const hsPattern = NoiseHandshakePatterns.WakuPairing;

    // Alice static/ephemeral key initialization and commitment
    const aliceStaticKey = generateX25519KeyPair();
    const aliceEphemeralKey = generateX25519KeyPair();
    const s = randomBytes(32, rng);
    const aliceCommittedStaticKey = commitPublicKey(aliceStaticKey.publicKey, s);

    // Bob static/ephemeral key initialization and commitment
    const bobStaticKey = generateX25519KeyPair();
    const bobEphemeralKey = generateX25519KeyPair();
    const r = randomBytes(32, rng);
    const bobCommittedStaticKey = commitPublicKey(bobStaticKey.publicKey, r);

    // Content topic information
    const applicationName = "waku-noise-sessions";
    const applicationVersion = "0.1";
    const shardId = "10";
    const qrMessageNameTag = randomBytes(MessageNametagLength, rng);

    // Out-of-band Communication

    // Bob prepares the QR and sends it out-of-band to Alice
    const qr = toQr(applicationName, applicationVersion, shardId, bobEphemeralKey.publicKey, bobCommittedStaticKey);
    const enc = new TextEncoder();
    const qrBytes = enc.encode(qr);

    // Alice deserializes the QR code
    const readQR = fromQr(qr);

    // We check if QR serialization/deserialization works
    expect(readQR.applicationName).to.be.equals(applicationName);
    expect(readQR.applicationVersion).to.be.equals(applicationVersion);
    expect(readQR.shardId).to.be.equals(shardId);
    expect(uint8ArrayEquals(bobEphemeralKey.publicKey, readQR.ephemeralKey)).to.be.true;
    expect(uint8ArrayEquals(bobCommittedStaticKey, readQR.committedStaticKey)).to.be.true;

    // We set the contentTopic from the content topic parameters exchanged in the QR
    const contentTopic =
      "/" + applicationName + "/" + applicationVersion + "/wakunoise/1/sessions_shard-" + shardId + "/proto";

    // Pre-handshake message
    // <- eB {H(sB||r), contentTopicParams, messageNametag}
    const preMessagePKs = [NoisePublicKey.fromPublicKey(bobEphemeralKey.publicKey)];

    // We initialize the Handshake states.
    // Note that we pass the whole qr serialization as prologue information
    const aliceHS = new Handshake({
      hsPattern,
      ephemeralKey: aliceEphemeralKey,
      staticKey: aliceStaticKey,
      prologue: qrBytes,
      preMessagePKs,
      initiator: true,
    });
    const bobHS = new Handshake({
      hsPattern,
      ephemeralKey: bobEphemeralKey,
      staticKey: bobStaticKey,
      prologue: qrBytes,
      preMessagePKs,
    });

    // Pairing Handshake
    // ==========

    // Write and read calls alternate between Alice and Bob: the handhshake progresses by alternatively calling stepHandshake for each user

    // 1st step
    // -> eA, eAeB   {H(sA||s)}   [authcode]

    // The messageNametag for the first handshake message is randomly generated and exchanged out-of-band
    // and corresponds to qrMessageNametag

    // We set the transport message to be H(sA||s)
    let sentTransportMessage = aliceCommittedStaticKey;

    // By being the handshake initiator, Alice writes a Waku2 payload v2 containing her handshake message
    // and the (encrypted) transport message
    // The message is sent with a messageNametag equal to the one received through the QR code
    let aliceStep = aliceHS.stepHandshake({
      transportMessage: sentTransportMessage,
      messageNametag: qrMessageNameTag,
    });

    let encoder = new NoiseHandshakeEncoder(contentTopic, aliceStep);

    // We prepare a Waku message from Alice's payload2
    // At this point wakuMsg is sent over the Waku network and is received
    // We simulate this by creating the ProtoBuffer from wakuMsg
    let wakuMsgBytes = await encoder.encode({});

    // We decode the WakuMessage from the ProtoBuffer
    let decoder = new NoiseHandshakeDecoder(contentTopic);
    let wakuMsgProto = await decoder.decodeProto(wakuMsgBytes!);
    let v2Msg = await decoder.decode(wakuMsgProto!);

    expect(v2Msg!.contentTopic).to.be.equals(contentTopic);
    expect(v2Msg?.payloadV2.equals(aliceStep.payload2)).to.be.true;

    // Bob reads Alice's payloads, and returns the (decrypted) transport message Alice sent to him
    // Note that Bob verifies if the received payloadv2 has the expected messageNametag set
    let bobStep = bobHS.stepHandshake({ readPayloadV2: v2Msg?.payloadV2, messageNametag: qrMessageNameTag });

    expect(uint8ArrayEquals(bobStep.transportMessage, sentTransportMessage));

    // We generate an authorization code using the handshake state
    const aliceAuthcode = aliceHS.genAuthcode();
    const bobAuthcode = bobHS.genAuthcode();

    // We check that they are equal. Note that this check has to be confirmed with a user interaction.
    expect(aliceAuthcode).to.be.equals(bobAuthcode);

    // 2nd step
    // <- sB, eAsB    {r}

    // Alice and Bob update their local next messageNametag using the available handshake information
    // During the handshake, messageNametag = HKDF(h), where h is the handshake hash value at the end of the last processed message
    let aliceMessageNametag = aliceHS.hs.toMessageNametag();
    let bobMessageNametag = bobHS.hs.toMessageNametag();

    // We set as a transport message the commitment randomness r
    sentTransportMessage = r;

    // At this step, Bob writes and returns a payload
    bobStep = bobHS.stepHandshake({ transportMessage: sentTransportMessage, messageNametag: bobMessageNametag });

    // We prepare a Waku message from Bob's payload2
    encoder = new NoiseHandshakeEncoder(contentTopic, bobStep);

    // At this point wakuMsg is sent over the Waku network and is received
    // We simulate this by creating the ProtoBuffer from wakuMsg
    wakuMsgBytes = await encoder.encode({});

    // We decode the WakuMessage from the ProtoBuffer
    decoder = new NoiseHandshakeDecoder(contentTopic);
    wakuMsgProto = await decoder.decodeProto(wakuMsgBytes!);
    v2Msg = await decoder.decode(wakuMsgProto!);

    expect(v2Msg?.payloadV2.equals(bobStep.payload2)).to.be.true;

    // While Alice reads and returns the (decrypted) transport message
    aliceStep = aliceHS.stepHandshake({ readPayloadV2: v2Msg?.payloadV2, messageNametag: aliceMessageNametag });

    expect(uint8ArrayEquals(aliceStep.transportMessage, sentTransportMessage));

    // Alice further checks if Bob's commitment opens to Bob's static key she just received
    const expectedBobCommittedStaticKey = commitPublicKey(aliceHS.hs.rs!, aliceStep.transportMessage);

    expect(uint8ArrayEquals(expectedBobCommittedStaticKey, bobCommittedStaticKey)).to.be.true;

    // 3rd step
    // -> sA, sAeB, sAsB  {s}

    // Alice and Bob update their local next messageNametag using the available handshake information
    aliceMessageNametag = aliceHS.hs.toMessageNametag();
    bobMessageNametag = bobHS.hs.toMessageNametag();

    // We set as a transport message the commitment randomness s
    sentTransportMessage = s;

    // Similarly as in first step, Alice writes a Waku2 payload containing the handshake message and the (encrypted) transport message
    aliceStep = aliceHS.stepHandshake({ transportMessage: sentTransportMessage, messageNametag: aliceMessageNametag });

    // We prepare a Waku message from Alice's payload2
    encoder = new NoiseHandshakeEncoder(contentTopic, aliceStep);

    // At this point wakuMsg is sent over the Waku network and is received
    // We simulate this by creating the ProtoBuffer from wakuMsg
    wakuMsgBytes = await encoder.encode({});

    // We decode the WakuMessage from the ProtoBuffer
    decoder = new NoiseHandshakeDecoder(contentTopic);
    wakuMsgProto = await decoder.decodeProto(wakuMsgBytes!);
    v2Msg = await decoder.decode(wakuMsgProto!);

    expect(v2Msg?.payloadV2.equals(aliceStep.payload2)).to.be.true;

    // Bob reads Alice's payloads, and returns the (decrypted) transport message Alice sent to him
    bobStep = bobHS.stepHandshake({ readPayloadV2: v2Msg?.payloadV2, messageNametag: bobMessageNametag });

    expect(uint8ArrayEquals(bobStep.transportMessage, sentTransportMessage));

    // Bob further checks if Alice's commitment opens to Alice's static key he just received
    const expectedAliceCommittedStaticKey = commitPublicKey(bobHS.hs.rs!, bobStep.transportMessage);

    expect(uint8ArrayEquals(expectedAliceCommittedStaticKey, aliceCommittedStaticKey)).to.be.true;

    // Secure Transfer Phase
    // ==========

    //  We finalize the handshake to retrieve the Inbound/Outbound Symmetric States
    const aliceHSResult = aliceHS.finalizeHandshake();
    const bobHSResult = bobHS.finalizeHandshake();

    const aliceEncoder = new NoiseSecureTransferEncoder(contentTopic, aliceHSResult);
    const bobEncoder = new NoiseSecureTransferEncoder(contentTopic, bobHSResult);

    const aliceDecoder = new NoiseSecureTransferDecoder(contentTopic, aliceHSResult);
    const bobDecoder = new NoiseSecureTransferDecoder(contentTopic, bobHSResult);

    // We test read/write of random messages exchanged between Alice and Bob
    // Note that we exchange more than the number of messages contained in the nametag buffer to test if they are filled correctly as the communication proceeds
    for (let i = 0; i < 10 * MessageNametagBufferSize; i++) {
      // Alice writes to Bob
      let message = randomBytes(32, rng);
      let encodedMsg = await aliceEncoder.encode({ payload: message });
      let readMessageProto = await bobDecoder.decodeProto(encodedMsg!);
      let readMessage = await bobDecoder.decode(readMessageProto!);

      expect(uint8ArrayEquals(message, readMessage!.payload)).to.be.true;

      // Bob writes to Alice
      message = randomBytes(32, rng);
      encodedMsg = await bobEncoder.encode({ payload: message });
      readMessageProto = await aliceDecoder.decodeProto(encodedMsg!);
      readMessage = await aliceDecoder.decode(readMessageProto!);

      expect(uint8ArrayEquals(message, readMessage!.payload)).to.be.true;
    }

    // TODO
    // TODO
    // TODO
    // TODO
    // TODO
    /*
    // We test how nametag buffers help in detecting lost messages
    // Alice writes two messages to Bob, but only the second is received
    try {
      const message = randomBytes(32, rng);
      payload2 = aliceHSResult.writeMessage(message, aliceHSResult.nametagsOutbound);
      message = randomBytes(32, rng);
      payload2 = aliceHSResult.writeMessage(aliceHSResult.nametagsOutbound);
    } catch (NoiseSomeMessagesWereLost) {
      let readMessage = readMessage(
        bobHSResult,
        payload2,
        (inboundMessageNametagBuffer = bobHSResult.nametagsInbound)
      ).get();
    }

    // We adjust bob nametag buffer for next test (i.e. the missed message is correctly recovered)
    bobHSResult.nametagsInbound.delete(2);
    let message = randomBytes(32, rng);
    payload2 = writeMessage(bobHSResult, message, (outboundMessageNametagBuffer = bobHSResult.nametagsOutbound));
    readMessage = readMessage(
      aliceHSResult,
      payload2,
      (inboundMessageNametagBuffer = aliceHSResult.nametagsInbound)
    ).get();

    expect(uint8ArrayEquals(message, readMessage!.payload)).to.be.true;

    // We test if a missing nametag is correctly detected
    try {
      const message = randomBytes(32, rng);
      const payload2 = aliceHSResult.writeMessage(message, aliceHSResult.nametagsOutbound);
      bobHSResult.nametagsInbound.delete(1);
    } catch (NoiseMessageNametagError) {
      let readMessage = readMessage(
        bobHSResult,
        payload2,
        (inboundMessageNametagBuffer = bobHSResult.nametagsInbound)
      ).get();
    }
    */
  });
});
