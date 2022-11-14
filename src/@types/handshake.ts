import type { bytes } from "./basic.js";

export type Hkdf = [bytes, bytes, bytes];

// a transport message (for Noise handshakes and ChaChaPoly encryptions)
export type MessageNametag = Uint8Array;
