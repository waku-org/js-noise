import { HMACDRBG } from "@stablelib/hmac-drbg";
import { randomBytes } from "@stablelib/random";
import { expect } from "chai";
import { equals as uint8ArrayEquals } from "uint8arrays/equals";

import { chaCha20Poly1305Encrypt, dh, generateX25519KeyPair } from "./crypto";
import { CipherState } from "./noise";
import { MAX_NONCE, Nonce } from "./nonce";

function randomCipherState(rng: HMACDRBG, nonce: number = 0): CipherState {
  const randomCipherState = new CipherState();
  randomCipherState.n = new Nonce(nonce);
  randomCipherState.k = rng.randomBytes(32);
  return randomCipherState;
}

describe("js-noise", () => {
  it("Noise State Machine: Diffie-Hellman operation", function () {
    const aliceKey = generateX25519KeyPair();
    const bobKey = generateX25519KeyPair();

    // A Diffie-Hellman operation between Alice's private key and Bob's public key must be equal to
    // a Diffie-hellman operation between Alice's public key and Bob's private key
    const dh1 = dh(aliceKey.privateKey, bobKey.publicKey);
    const dh2 = dh(bobKey.privateKey, aliceKey.publicKey);

    expect(uint8ArrayEquals(dh1, dh2)).to.be.true;
  });

  it("Noise State Machine: Cipher State primitives", function () {
    const rng = new HMACDRBG();

    // We generate a random Cipher State, associated data ad and plaintext
    let cipherState = randomCipherState(rng);
    let nonceValue = Math.floor(Math.random() * MAX_NONCE);
    const ad = randomBytes(128, rng);
    let plaintext = randomBytes(128, rng);
    let nonce = new Nonce(nonceValue);

    // We set the random nonce generated in the cipher state
    cipherState.setNonce(nonce);

    // We perform encryption
    let ciphertext = cipherState.encryptWithAd(ad, plaintext);

    // After any encryption/decryption operation, the Cipher State's nonce increases by 1
    expect(cipherState.getNonce().getUint64()).to.be.equals(nonceValue + 1);

    // We set the nonce back to its original value for decryption
    cipherState.setNonce(new Nonce(nonceValue));

    // We decrypt (using the original nonce)
    const decrypted = cipherState.decryptWithAd(ad, ciphertext);

    // We check if encryption and decryption are correct and that nonce correctly increased after decryption
    expect(cipherState.getNonce().getUint64()).to.be.equals(nonceValue + 1);
    expect(uint8ArrayEquals(plaintext, decrypted)).to.be.true;

    // If a Cipher State has no key set, encryptWithAd should return the plaintext without increasing the nonce
    cipherState.setCipherStateKey(CipherState.createEmptyKey());
    nonce = cipherState.getNonce();
    nonceValue = nonce.getUint64();
    plaintext = randomBytes(128, rng);
    ciphertext = cipherState.encryptWithAd(ad, plaintext);

    expect(uint8ArrayEquals(ciphertext, plaintext)).to.be.true;
    expect(cipherState.getNonce().getUint64()).to.be.equals(nonceValue);

    // If a Cipher State has no key set, decryptWithAd should return the ciphertext without increasing the nonce
    cipherState.setCipherStateKey(CipherState.createEmptyKey());
    nonce = cipherState.getNonce();
    nonceValue = nonce.getUint64();
    ciphertext = randomBytes(128, rng);
    plaintext = cipherState.decryptWithAd(ad, ciphertext);

    expect(uint8ArrayEquals(ciphertext, plaintext)).to.be.true;
    expect(cipherState.getNonce().getUint64()).to.be.equals(nonceValue);

    // A Cipher State cannot have a nonce greater or equal 0xffffffff in this implementation (see nonce.ts for details)
    // Note that nonce is increased after each encryption and decryption operation

    // We generate a test Cipher State with nonce set to MaxNonce
    cipherState = randomCipherState(rng);
    cipherState.setNonce(new Nonce(MAX_NONCE));
    plaintext = randomBytes(128, rng);

    // We test if encryption fails. Any subsequent encryption call over the Cipher State should fail similarly and leave the nonce unchanged
    for (let i = 0; i < 5; i++) {
      try {
        ciphertext = cipherState.encryptWithAd(ad, plaintext);
        expect(true).to.be.false; // Should not reach this line
      } catch (err) {
        // Do nothing
      }
      expect(cipherState.getNonce().getUint64()).to.be.equals(MAX_NONCE + 1);
    }

    // We generate a test Cipher State
    // Since nonce is increased after decryption as well, we need to generate a proper ciphertext in order to test MaxNonceError error handling
    // We cannot call encryptWithAd to encrypt a plaintext using a nonce equal MaxNonce, since this will trigger a MaxNonceError.
    // To perform such test, we then need to encrypt a test plaintext using directly ChaChaPoly primitive
    cipherState = randomCipherState(rng);
    cipherState.setNonce(new Nonce(MAX_NONCE));
    plaintext = randomBytes(128, rng);

    // We perform encryption using the Cipher State key, NonceMax and ad
    ciphertext = chaCha20Poly1305Encrypt(
      plaintext,
      cipherState.getNonce().getBytes(),
      ad,
      cipherState.getKey()
    );

    // At this point ciphertext is a proper encryption of the original plaintext obtained with nonce equal to NonceMax
    // We can now test if decryption fails with a NoiseNonceMaxError error. Any subsequent decryption call over the Cipher State should fail similarly and leave the nonce unchanged
    // Note that decryptWithAd doesn't fail in decrypting the ciphertext (otherwise a NoiseDecryptTagError would have been triggered)
    for (let i = 0; i < 5; i++) {
      try {
        plaintext = cipherState.decryptWithAd(ad, ciphertext);
        expect(true).to.be.false; // Should not reach this line
      } catch (err) {
        // Do nothing
      }

      expect(cipherState.getNonce().getUint64()).to.be.equals(MAX_NONCE + 1);
    }
  });
});
