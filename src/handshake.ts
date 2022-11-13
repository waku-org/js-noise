import * as pkcs7 from "pkcs7-padding";

import { bytes32 } from "./@types/basic.js";
import type { KeyPair } from "./@types/keypair.js";
import {
  Curve25519KeySize,
  dh,
  generateX25519KeyPair,
  intoCurve25519Key,
} from "./crypto.js";
import { SymmetricState } from "./noise.js";
import {
  EmptyPreMessage,
  HandshakePattern,
  MessageDirection,
  NoiseTokens,
  PreMessagePattern,
} from "./patterns";
import { NoisePublicKey } from "./publickey.js";

// The padding blocksize of  a transport message
const NoisePaddingBlockSize = 248;

// The Handshake State as in https://noiseprotocol.org/noise.html#the-handshakestate-object
// Contains
//   - the local and remote ephemeral/static keys e,s,re,rs (if any)
//   - the initiator flag (true if the user creating the state is the handshake initiator, false otherwise)
//   - the handshakePattern (containing the handshake protocol name, and (pre)message patterns)
// This object is futher extended from specifications by storing:
//   - a message pattern index msgPatternIdx indicating the next handshake message pattern to process
//   - the user's preshared psk, if any
export class HandshakeState {
  s?: KeyPair;
  e?: KeyPair;
  rs?: bytes32;
  re?: bytes32;
  ss: SymmetricState;
  initiator: boolean;
  handshakePattern: HandshakePattern;
  msgPatternIdx: number;
  psk: Uint8Array;

  constructor(hsPattern: HandshakePattern, psk: Uint8Array) {
    // By default the Handshake State initiator flag is set to false
    // Will be set to true when the user associated to the handshake state starts an handshake
    this.initiator = false;

    this.handshakePattern = hsPattern;
    this.psk = psk;

    this.ss = new SymmetricState(hsPattern);

    this.msgPatternIdx = 0;
  }

  // Handshake Processing

  // Based on the message handshake direction and if the user is or not the initiator, returns a boolean tuple telling if the user
  // has to read or write the next handshake message
  getReadingWritingState(direction: MessageDirection): {
    reading: boolean;
    writing: boolean;
  } {
    let reading = false;
    let writing = false;

    if (this.initiator && direction == MessageDirection.r) {
      // I'm Alice and direction is ->
      reading = false;
      writing = true;
    } else if (this.initiator && direction == MessageDirection.l) {
      // I'm Alice and direction is <-
      reading = true;
      writing = false;
    } else if (!this.initiator && direction == MessageDirection.r) {
      // I'm Bob and direction is ->
      reading = true;
      writing = false;
    } else if (!this.initiator && direction == MessageDirection.l) {
      // I'm Bob and direction is <-
      reading = false;
      writing = true;
    }
    return { reading, writing };
  }

  // Checks if a pre-message is valid according to Noise specifications
  // http://www.noiseprotocol.org/noise.html#handshake-patterns
  isValid(msg: Array<PreMessagePattern>): boolean {
    let isValid = true;

    // Non-empty pre-messages can only have patterns "e", "s", "e,s" in each direction
    const allowedPatterns = [
      new PreMessagePattern(MessageDirection.r, [NoiseTokens.s]),
      new PreMessagePattern(MessageDirection.r, [NoiseTokens.e]),
      new PreMessagePattern(MessageDirection.r, [NoiseTokens.e, NoiseTokens.s]),
      new PreMessagePattern(MessageDirection.l, [NoiseTokens.s]),
      new PreMessagePattern(MessageDirection.l, [NoiseTokens.e]),
      new PreMessagePattern(MessageDirection.l, [NoiseTokens.e, NoiseTokens.s]),
    ];

    // We check if pre message patterns are allowed
    for (const pattern of msg) {
      if (!allowedPatterns.find((x) => x.equals(pattern))) {
        isValid = false;
        break;
      }
    }

    return isValid;
  }

  // Handshake messages processing procedures

  // Processes pre-message patterns
  processPreMessagePatternTokens(
    inPreMessagePKs: Array<NoisePublicKey> = []
  ): void {
    // I make a copy of the input pre-message public keys, so that I can easily delete processed ones without using iterators/counters
    const preMessagePKs = inPreMessagePKs;

    // Here we store currently processed pre message public key
    let currPK: NoisePublicKey;

    // We retrieve the pre-message patterns to process, if any
    // If none, there's nothing to do
    if (this.handshakePattern.preMessagePatterns == EmptyPreMessage) {
      return;
    }

    // If not empty, we check that pre-message is valid according to Noise specifications
    if (!this.isValid(this.handshakePattern.preMessagePatterns)) {
      throw "invalid pre-message in handshake";
    }

    // We iterate over each pattern contained in the pre-message
    for (const messagePattern of this.handshakePattern.preMessagePatterns) {
      const direction = messagePattern.direction;
      const tokens = messagePattern.tokens;

      // We get if the user is reading or writing the current pre-message pattern
      const { reading, writing } = this.getReadingWritingState(direction);

      // We process each message pattern token
      for (const token of tokens) {
        // We process the pattern token
        switch (token) {
          case NoiseTokens.e:
            // We expect an ephemeral key, so we attempt to read it (next PK to process will always be at index 0 of preMessagePKs)
            if (preMessagePKs.length > 0) {
              currPK = preMessagePKs[0];
            } else {
              throw "noise pre-message read e, expected a public key";
            }

            // If user is reading the "e" token
            if (reading) {
              console.trace("noise pre-message read e");

              // We check if current key is encrypted or not. We assume pre-message public keys are all unencrypted on users' end
              if (currPK.flag == 0) {
                // Sets re and calls MixHash(re.public_key).
                this.re = intoCurve25519Key(currPK.pk);
                this.ss.mixHash(this.re);
              } else {
                throw "noise read e, incorrect encryption flag for pre-message public key";
              }
              // If user is writing the "e" token
            } else if (writing) {
              console.trace("noise pre-message write e");

              // When writing, the user is sending a public key,
              // We check that the public part corresponds to the set local key and we call MixHash(e.public_key).
              if (this.e && this.e.publicKey == intoCurve25519Key(currPK.pk)) {
                this.ss.mixHash(this.e.publicKey);
              } else {
                throw "noise pre-message e key doesn't correspond to locally set e key pair";
              }
            }

            // Noise specification: section 9.2
            // In non-PSK handshakes, the "e" token in a pre-message pattern or message pattern always results
            // in a call to MixHash(e.public_key).
            // In a PSK handshake, all of these calls are followed by MixKey(e.public_key).
            if (this.handshakePattern.name.indexOf("psk") > -1) {
              this.ss.mixKey(currPK.pk);
            }

            // We delete processed public key
            preMessagePKs.shift();
            break;
          case NoiseTokens.s:
            // We expect a static key, so we attempt to read it (next PK to process will always be at index of preMessagePKs)
            if (preMessagePKs.length > 0) {
              currPK = preMessagePKs[0];
            } else {
              throw "noise pre-message read s, expected a public key";
            }

            // If user is reading the "s" token
            if (reading) {
              console.trace("noise pre-message read s");

              // We check if current key is encrypted or not. We assume pre-message public keys are all unencrypted on users' end
              if (currPK.flag == 0) {
                // Sets re and calls MixHash(re.public_key).
                this.rs = intoCurve25519Key(currPK.pk);
                this.ss.mixHash(this.rs);
              } else {
                throw "noise read s, incorrect encryption flag for pre-message public key";
              }

              // If user is writing the "s" token
            } else if (writing) {
              console.trace("noise pre-message write s");

              // If writing, it means that the user is sending a public key,
              // We check that the public part corresponds to the set local key and we call MixHash(s.public_key).
              if (this.s && this.s.publicKey == intoCurve25519Key(currPK.pk)) {
                this.ss.mixHash(this.s.publicKey);
              } else {
                throw "noise pre-message s key doesn't correspond to locally set s key pair";
              }
            }

            // Noise specification: section 9.2
            // In non-PSK handshakes, the "e" token in a pre-message pattern or message pattern always results
            // in a call to MixHash(e.public_key).
            // In a PSK handshake, all of these calls are followed by MixKey(e.public_key).
            if (this.handshakePattern.name.indexOf("psk") > -1) {
              this.ss.mixKey(currPK.pk);
            }

            // We delete processed public key
            preMessagePKs.shift();
            break;
          default:
            throw "invalid Token for pre-message pattern";
        }
      }
    }
  }

  // This procedure encrypts/decrypts the implicit payload attached at the end of every message pattern
  // An optional extraAd to pass extra additional data in encryption/decryption can be set (useful to authenticate messageNametag)
  processMessagePatternPayload(
    transportMessage: Uint8Array,
    extraAd: Uint8Array = new Uint8Array()
  ): Uint8Array {
    let payload: Uint8Array;

    // We retrieve current message pattern (direction + tokens) to process
    const direction =
      this.handshakePattern.messagePatterns[this.msgPatternIdx].direction;

    // We get if the user is reading or writing the input handshake message
    const { reading, writing } = this.getReadingWritingState(direction);

    // We decrypt the transportMessage, if any
    if (reading) {
      payload = this.ss.decryptAndHash(transportMessage, extraAd);
      payload = pkcs7.pad(payload, NoisePaddingBlockSize);
    } else if (writing) {
      payload = pkcs7.unpad(transportMessage);
      payload = this.ss.encryptAndHash(payload, extraAd);
    } else {
      throw "undefined state";
    }
    return payload;
  }

  // We process an input handshake message according to current handshake state and we return the next handshake step's handshake message
  processMessagePatternTokens(
    inputHandshakeMessage: Array<NoisePublicKey> = []
  ): Array<NoisePublicKey> {
    // We retrieve current message pattern (direction + tokens) to process
    const messagePattern =
      this.handshakePattern.messagePatterns[this.msgPatternIdx];
    const direction = messagePattern.direction;
    const tokens = messagePattern.tokens;

    // We get if the user is reading or writing the input handshake message
    const { reading, writing } = this.getReadingWritingState(direction);

    // I make a copy of the handshake message so that I can easily delete processed PKs without using iterators/counters
    // (Possibly) non-empty if reading
    const inHandshakeMessage = inputHandshakeMessage;

    // The party's output public keys
    // (Possibly) non-empty if writing
    const outHandshakeMessage: Array<NoisePublicKey> = [];

    // In currPK we store the currently processed public key from the handshake message
    let currPK: NoisePublicKey;

    // We process each message pattern token
    for (const token of tokens) {
      switch (token) {
        case NoiseTokens.e:
          // If user is reading the "s" token
          if (reading) {
            console.trace("noise read e");

            // We expect an ephemeral key, so we attempt to read it (next PK to process will always be at index 0 of preMessagePKs)
            if (inHandshakeMessage.length > 0) {
              currPK = inHandshakeMessage[0];
            } else {
              throw "noise read e, expected a public key";
            }

            // We check if current key is encrypted or not
            // Note: by specification, ephemeral keys should always be unencrypted. But we support encrypted ones.
            if (currPK.flag == 0) {
              // Unencrypted Public Key
              // Sets re and calls MixHash(re.public_key).
              this.re = intoCurve25519Key(currPK.pk);
              this.ss.mixHash(this.re);

              // The following is out of specification: we call decryptAndHash for encrypted ephemeral keys, similarly as happens for (encrypted) static keys
            } else if (currPK.flag == 1) {
              // Encrypted public key
              // Decrypts re, sets re and calls MixHash(re.public_key).
              this.re = intoCurve25519Key(this.ss.decryptAndHash(currPK.pk));
            } else {
              throw "noise read e, incorrect encryption flag for public key";
            }

            // Noise specification: section 9.2
            // In non-PSK handshakes, the "e" token in a pre-message pattern or message pattern always results
            // in a call to MixHash(e.public_key).
            // In a PSK handshake, all of these calls are followed by MixKey(e.public_key).
            if (this.handshakePattern.name.indexOf("psk") > -1) {
              this.ss.mixKey(this.re);
            }

            // We delete processed public key
            inHandshakeMessage.shift();

            // If user is writing the "e" token
          } else if (writing) {
            console.trace("noise write e");

            // We generate a new ephemeral keypair
            this.e = generateX25519KeyPair();

            // We update the state
            this.ss.mixHash(this.e.publicKey);

            // Noise specification: section 9.2
            // In non-PSK handshakes, the "e" token in a pre-message pattern or message pattern always results
            // in a call to MixHash(e.public_key).
            // In a PSK handshake, all of these calls are followed by MixKey(e.public_key).
            if (this.handshakePattern.name.indexOf("psk") > -1) {
              this.ss.mixKey(this.e.publicKey);
            }

            // We add the ephemeral public key to the Waku payload
            outHandshakeMessage.push(NoisePublicKey.to(this.e.publicKey));
          }
          break;

        case NoiseTokens.s:
          // If user is reading the "s" token
          if (reading) {
            console.trace("noise read s");

            // We expect a static key, so we attempt to read it (next PK to process will always be at index 0 of preMessagePKs)
            if (inHandshakeMessage.length > 0) {
              currPK = inHandshakeMessage[0];
            } else {
              throw "noise read s, expected a public key";
            }

            // We check if current key is encrypted or not
            if (currPK.flag == 0) {
              // Unencrypted Public Key
              // Sets re and calls MixHash(re.public_key).
              this.rs = intoCurve25519Key(currPK.pk);
              this.ss.mixHash(this.rs);
            } else if (currPK.flag == 1) {
              // Encrypted public key
              // Decrypts rs, sets rs and calls MixHash(rs.public_key).
              this.rs = intoCurve25519Key(this.ss.decryptAndHash(currPK.pk));
            } else {
              throw "noise read s, incorrect encryption flag for public key";
            }

            // We delete processed public key
            inHandshakeMessage.shift();

            // If user is writing the "s" token
          } else if (writing) {
            console.trace("noise write s");

            // If the local static key is not set (the handshake state was not properly initialized), we raise an error
            if (!this.s) {
              throw "static key not set";
            }

            // We encrypt the public part of the static key in case a key is set in the Cipher State
            // That is, encS may either be an encrypted or unencrypted static key.
            const encS = this.ss.encryptAndHash(this.s.publicKey);

            // We add the (encrypted) static public key to the Waku payload
            // Note that encS = (Enc(s) || tag) if encryption key is set, otherwise encS = s.
            // We distinguish these two cases by checking length of encryption and we set the proper encryption flag
            if (encS.length > Curve25519KeySize) {
              outHandshakeMessage.push(new NoisePublicKey(1, encS));
            } else {
              outHandshakeMessage.push(new NoisePublicKey(0, encS));
            }
          }

          break;

        case NoiseTokens.psk:
          // If user is reading the "psk" token

          console.trace("noise psk");

          // Calls MixKeyAndHash(psk)
          this.ss.mixKeyAndHash(this.psk);
          break;

        case NoiseTokens.ee:
          // If user is reading the "ee" token

          console.trace("noise dh ee");

          // If local and/or remote ephemeral keys are not set, we raise an error
          if (!this.e || !this.re) {
            throw "local or remote ephemeral key not set";
          }

          // Calls MixKey(DH(e, re)).
          this.ss.mixKey(dh(this.e.privateKey, this.re));
          break;

        case NoiseTokens.es:
          // If user is reading the "es" token

          console.trace("noise dh es");

          // We check if keys are correctly set.
          // If both present, we call MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
          if (this.initiator) {
            if (!this.e || !this.rs) {
              throw "local or remote ephemeral/static key not set";
            }

            this.ss.mixKey(dh(this.e.privateKey, this.rs));
          } else {
            if (!this.re || !this.s) {
              throw "local or remote ephemeral/static key not set";
            }

            this.ss.mixKey(dh(this.s.privateKey, this.re));
          }
          break;

        case NoiseTokens.se:
          // If user is reading the "se" token

          console.trace("noise dh se");

          // We check if keys are correctly set.
          // If both present, call MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
          if (this.initiator) {
            if (!this.s || !this.re) {
              throw "local or remote ephemeral/static key not set";
            }

            this.ss.mixKey(dh(this.s.privateKey, this.re));
          } else {
            if (!this.rs || !this.e) {
              throw "local or remote ephemeral/static key not set";
            }

            this.ss.mixKey(dh(this.e.privateKey, this.rs));
          }
          break;

        case NoiseTokens.ss:
          // If user is reading the "ss" token

          console.trace("noise dh ss");

          // If local and/or remote static keys are not set, we raise an error
          if (!this.s || !this.rs) {
            throw "local or remote static key not set";
          }

          // Calls MixKey(DH(s, rs)).
          this.ss.mixKey(dh(this.s.privateKey, this.rs));
          break;
      }
    }

    return outHandshakeMessage;
  }
}
