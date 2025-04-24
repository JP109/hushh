import { WebSocketServer } from "ws";
import { randomBytes } from "crypto";
import { modPow, MODP_P, g, randomBigInt, bigintToBytes } from "./crypto/dh.js";
import { deriveAESKeyAndIV } from "./crypto/keyDerivation.js";
import { computeMsgKey } from "./crypto/msgKey.js";
import { aesIgeEncrypt, aesIgeDecrypt } from "./crypto/aesIge.js";
import { register, decodeTLObject, encodeTLObject } from "./tl/tl.js";

register({
  id: 0x5c4d7a1f,
  name: "message",
  args: [{ name: "text", type: "string" }],
});

const clients = new Map();

const wss = new WebSocketServer({ port: 8080 }, () => {
  console.log("✅ MTProto WebSocket server running on ws://localhost:8080");
});

function generateMsgId() {
  const unixSeconds = BigInt(Math.floor(Date.now() / 1000));
  const milliseconds = BigInt(Date.now() % 1000);
  const random = BigInt(Math.floor(Math.random() * 4));
  return (unixSeconds << 32n) | (milliseconds << 22n) | (random << 2n);
}

wss.on("connection", (ws) => {
  console.log("🔌 Client connected");

  let serverPriv = randomBigInt();
  let g_b = modPow(g, serverPriv, MODP_P);
  let gBBytes = bigintToBytes(g_b);

  ws.once("message", (msg) => {
    const gA = BigInt("0x" + Buffer.from(msg).toString("hex"));
    const g_ab = modPow(gA, serverPriv, MODP_P);
    const authKey = bigintToBytes(g_ab, 256);
    const authKeyId = authKey.subarray(256 - 8);
    const serverSalt = randomBytes(8);
    const sessionId = randomBytes(8);

    clients.set(ws, {
      authKey,
      authKeyId,
      serverSalt,
      sessionId,
      seqno: 0,
    });

    ws.send(gBBytes);
    console.log("🔐 Auth key established");
  });

  ws.on("message", (data) => {
    if (!clients.has(ws)) return;
    const client = clients.get(ws);
    const { authKey, authKeyId, serverSalt, sessionId } = client;

    const msgKey = data.subarray(8, 24);
    const ciphertext = data.subarray(24);

    const { aesKey, aesIV } = deriveAESKeyAndIV(authKey, msgKey, false);
    const plaintext = aesIgeDecrypt(ciphertext, aesKey, aesIV);
    const body = plaintext.subarray(32);

    const decoded = decodeTLObject(body);
    if (decoded._ === "message") {
      console.log("📩 Client says:", decoded.text);
    }

    const replyBody = encodeTLObject({
      _: "message",
      text: `You said: ${decoded.text}`,
    });
    const innerMsgId = generateMsgId();
    const innerSeqNo = client.seqno;
    client.seqno += 2;

    const innerHeader = Buffer.alloc(16);
    innerHeader.writeBigUInt64LE(innerMsgId, 0);
    innerHeader.writeUInt32LE(innerSeqNo, 8);
    innerHeader.writeUInt32LE(replyBody.length, 12);
    const innerMessage = Buffer.concat([innerHeader, replyBody]);

    const containerConstructor = Buffer.from("dcf8f173", "hex").reverse();
    const count = Buffer.alloc(4);
    count.writeUInt32LE(1, 0);
    const containerBody = Buffer.concat([
      containerConstructor,
      count,
      innerMessage,
    ]);

    const outerMsgId = generateMsgId();
    const outerSeqno = client.seqno;
    client.seqno += 2;

    const outerHeader = Buffer.alloc(32);
    serverSalt.copy(outerHeader, 0);
    sessionId.copy(outerHeader, 8);
    outerHeader.writeBigUInt64LE(outerMsgId, 16);
    outerHeader.writeUInt32LE(outerSeqno, 24);

    const fullPlaintext = Buffer.concat([outerHeader, containerBody]);
    const replyMsgKey = computeMsgKey(authKey, fullPlaintext);
    const { aesKey: aesKeyResp, aesIV: aesIVResp } = deriveAESKeyAndIV(
      authKey,
      replyMsgKey,
      true
    );
    const encryptedReply = aesIgeEncrypt(fullPlaintext, aesKeyResp, aesIVResp);
    ws.send(Buffer.concat([authKeyId, replyMsgKey, encryptedReply]));
  });
});
