import { createLightNode } from "js-waku/lib/create_waku";
import { waitForRemotePeer } from "js-waku/lib/wait_for_remote_peer";
import * as noise from "@waku/js-noise";
import QRCode from "qrcode";
// TODO: Get rid of these
import hexToArrayBuffer from "hex-to-array-buffer";
import arrayBufferToHex from "array-buffer-to-hex";

function getPairingInfo() {
  const urlParts = window.location.href.split("?");
  if (urlParts.length < 2) return undefined;

  const pairingParts = decodeURIComponent(urlParts[1]).split(":");
  if (pairingParts.length < 6) throw new Error("invalid pairing information format");

  const qrMessageNameTag = new Uint8Array(hexToArrayBuffer(pairingParts.shift()));

  return new noise.InitiatorParameters(pairingParts.join(":"), qrMessageNameTag);
}

async function confirmAuthCodeFlow(pairingObj) {
  const authCode = await pairingObj.getAuthCode();
  pairingObj.validateAuthCode(confirm("Confirm that authcode is: " + authCode));
}

async function main() {
  // Starting the node
  const node = await createLightNode();
  await node.start();

  // Dialing a node and wait until it's available
  const ma =
    "/dns4/node-01.ac-cn-hongkong-c.wakuv2.test.statusim.net/tcp/443/wss/p2p/16Uiu2HAkvWiyFsgRhuJEb9JfjYxEkoHLgnUQmr1N5mKWnYjxYRVm";
  await node.dial(ma, ["filter", "lightpush"]);
  await waitForRemotePeer(node, ["filter", "lightpush"]);

  const sender = {
    async publish(encoder, msg) {
      await node.lightPush.push(encoder, msg);
    },
  };

  const msgQueue = new Array();
  const receiver = {
    async subscribe(decoder) {
      await node.filter.subscribe([decoder], (wakuMessage) => {
        msgQueue.push(wakuMessage);
        // TODO: remove subscription once handshake ends?
      });
    },
    async nextMessage(contentTopic) {
      if (msgQueue.length != 0) {
        const oldestMsg = msgQueue.shift();
        if (oldestMsg.contentTopic === contentTopic) {
          return oldestMsg;
        }
      }

      return new Promise((resolve) => {
        const interval = setInterval(() => {
          if (msgQueue.length != 0) {
            clearInterval(interval);
            const oldestMsg = msgQueue.shift();
            if (oldestMsg.contentTopic === contentTopic) {
              resolve(oldestMsg);
            }
          }
        }, 100);
      });
    },
  };

  const myStaticKey = noise.generateX25519KeyPair();

  const pairingParameters = getPairingInfo();
  if (pairingParameters) {
    console.log("Initiator");

    const pairingObj = new noise.WakuPairing(sender, receiver, myStaticKey, pairingParameters);
    confirmAuthCodeFlow(pairingObj);
    try {
      console.log("executing handshake...");
      const codecs = await pairingObj.execute();
      alert("Handshake completed!");
      // TODO: enable a form so users can send messages
    } catch (err) {
      alert(err);
    }
  } else {
    console.log("Receiver");

    const pairingObj = new noise.WakuPairing(sender, receiver, myStaticKey, new noise.ReceiverParameters());
    const pExecute = pairingObj.execute();

    confirmAuthCodeFlow(pairingObj);

    const pInfo = pairingObj.getPairingInfo();

    // Data to encode in the QR code. The qrMessageNametag too to the QR string (separated by )
    const qrString = arrayBufferToHex(pInfo.qrMessageNameTag) + ":" + pInfo.qrCode;
    const qrURL = window.location.href + "?" + encodeURIComponent(qrString);

    console.log("Generating QR...")
    QRCode.toCanvas(document.getElementById("qrCanvas"), qrURL, (error) => {
      if (error) console.error(error);
    });

    // Auto open page - TODO: remove this
    window.setTimeout(() => {
      alert("Automatically opening new page to simulate QR code being scanned");
      window.open(qrURL);
    }, 1000);

    try {
      console.log("executing handshake...");
      const codecs = await pExecute;
      alert("Handshake completed!");
      // TODO: enable a form so users can send messages
    } catch (err) {
      // TODO: hide QR
      // TODO: display message indicating pairing is not valid
      // TODO: handle timeout
      alert(err);
    }
  }
}
main();
