// The Noise tokens appearing in Noise (pre)message patterns

// as in http://www.noiseprotocol.org/noise.html#handshake-pattern-basics
export enum NoiseTokens {
  e = "e",
  s = "s",
  es = "es",
  ee = "ee",
  se = "se",
  ss = "ss",
  psk = "psk",
}

// The direction of a (pre)message pattern in canonical form (i.e. Alice-initiated form)
// as in http://www.noiseprotocol.org/noise.html#alice-and-bob
export enum MessageDirection {
  r = "->",
  l = "<-",
}

// The pre message pattern consisting of a message direction and some Noise tokens, if any.
// (if non empty, only tokens e and s are allowed: http://www.noiseprotocol.org/noise.html#handshake-pattern-basics)
export class PreMessagePattern {
  constructor(public readonly direction: MessageDirection, public readonly tokens: Array<NoiseTokens>) {}

  equals(b: PreMessagePattern): boolean {
    return (
      this.direction == b.direction &&
      this.tokens.length === b.tokens.length &&
      this.tokens.every((val, index) => val === b.tokens[index])
    );
  }
}

// The message pattern consisting of a message direction and some Noise tokens
// All Noise tokens are allowed
export class MessagePattern {
  constructor(public readonly direction: MessageDirection, public readonly tokens: Array<NoiseTokens>) {}

  equals(b: MessagePattern): boolean {
    return (
      this.direction == b.direction &&
      this.tokens.length === b.tokens.length &&
      this.tokens.every((val, index) => val === b.tokens[index])
    );
  }
}

// The handshake pattern object. It stores the handshake protocol name, the handshake pre message patterns and the handshake message patterns
export class HandshakePattern {
  constructor(
    public readonly name: string,
    public readonly preMessagePatterns: Array<PreMessagePattern>,
    public readonly messagePatterns: Array<MessagePattern>
  ) {}

  equals(b: HandshakePattern): boolean {
    if (this.preMessagePatterns.length != b.preMessagePatterns.length) return false;
    for (let i = 0; i < this.preMessagePatterns.length; i++) {
      if (!this.preMessagePatterns[i].equals(b.preMessagePatterns[i])) return false;
    }

    if (this.messagePatterns.length != b.messagePatterns.length) return false;
    for (let i = 0; i < this.messagePatterns.length; i++) {
      if (!this.messagePatterns[i].equals(b.messagePatterns[i])) return false;
    }

    return this.name == b.name;
  }
}

// Constants (supported protocols)
export const EmptyPreMessage = new Array<PreMessagePattern>();

// Supported Noise handshake patterns as defined in https://rfc.vac.dev/spec/35/#specification
export const NoiseHandshakePatterns = {
  K1K1: new HandshakePattern(
    "Noise_K1K1_25519_ChaChaPoly_SHA256",
    [
      new PreMessagePattern(MessageDirection.r, [NoiseTokens.s]),
      new PreMessagePattern(MessageDirection.l, [NoiseTokens.s]),
    ],
    [
      new MessagePattern(MessageDirection.r, [NoiseTokens.e]),
      new MessagePattern(MessageDirection.l, [NoiseTokens.e, NoiseTokens.ee, NoiseTokens.es]),
      new MessagePattern(MessageDirection.r, [NoiseTokens.se]),
    ]
  ),
  XK1: new HandshakePattern(
    "Noise_XK1_25519_ChaChaPoly_SHA256",
    [new PreMessagePattern(MessageDirection.l, [NoiseTokens.s])],
    [
      new MessagePattern(MessageDirection.r, [NoiseTokens.e]),
      new MessagePattern(MessageDirection.l, [NoiseTokens.e, NoiseTokens.ee, NoiseTokens.es]),
      new MessagePattern(MessageDirection.r, [NoiseTokens.s, NoiseTokens.se]),
    ]
  ),
  XX: new HandshakePattern("Noise_XX_25519_ChaChaPoly_SHA256", EmptyPreMessage, [
    new MessagePattern(MessageDirection.r, [NoiseTokens.e]),
    new MessagePattern(MessageDirection.l, [NoiseTokens.e, NoiseTokens.ee, NoiseTokens.s, NoiseTokens.es]),
    new MessagePattern(MessageDirection.r, [NoiseTokens.s, NoiseTokens.se]),
  ]),
  XXpsk0: new HandshakePattern("Noise_XXpsk0_25519_ChaChaPoly_SHA256", EmptyPreMessage, [
    new MessagePattern(MessageDirection.r, [NoiseTokens.psk, NoiseTokens.e]),
    new MessagePattern(MessageDirection.l, [NoiseTokens.e, NoiseTokens.ee, NoiseTokens.s, NoiseTokens.es]),
    new MessagePattern(MessageDirection.r, [NoiseTokens.s, NoiseTokens.se]),
  ]),
  WakuPairing: new HandshakePattern(
    "Noise_WakuPairing_25519_ChaChaPoly_SHA256",
    [new PreMessagePattern(MessageDirection.l, [NoiseTokens.e])],
    [
      new MessagePattern(MessageDirection.r, [NoiseTokens.e, NoiseTokens.ee]),
      new MessagePattern(MessageDirection.l, [NoiseTokens.s, NoiseTokens.es]),
      new MessagePattern(MessageDirection.r, [NoiseTokens.s, NoiseTokens.se, NoiseTokens.ss]),
    ]
  ),
};

// Supported Protocol ID for PayloadV2 objects
// Protocol IDs are defined according to https://rfc.vac.dev/spec/35/#specification
export const PayloadV2ProtocolIDs = {
  "": 0,
  Noise_K1K1_25519_ChaChaPoly_SHA256: 10,
  Noise_XK1_25519_ChaChaPoly_SHA256: 11,
  Noise_XX_25519_ChaChaPoly_SHA256: 12,
  Noise_XXpsk0_25519_ChaChaPoly_SHA256: 13,
  Noise_WakuPairing_25519_ChaChaPoly_SHA256: 14,
  ChaChaPoly: 30,
};
