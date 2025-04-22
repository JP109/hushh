import { WebSocketServer } from "ws";
import { randomBytes } from "crypto";
import { modPow, MODP_P, g, randomBigInt, bigintToBytes } from "./crypto/dh.js";
import { deriveAESKeyAndIV } from "./crypto/keyDerivation.js";
import { computeMsgKey } from "./crypto/msgKey.js";
import { aesIgeEncrypt, aesIgeDecrypt } from "./crypto/aesIge.js";

const clients = new Map(); // socket → { authKey, authKeyId, serverSalt, sessionId, seqno }

const wss = new WebSocketServer({ port: 8080 }, () => {
  console.log("✅ MTProto WebSocket server running on ws://localhost:8080");
});

// 🔢 MTProto-compliant 64-bit message ID
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
    const authKeyId = authKey.subarray(256 - 8); // last 8 bytes

    const serverSalt = randomBytes(8);
    const sessionId = randomBytes(8);

    clients.set(ws, {
      authKey,
      authKeyId,
      serverSalt,
      sessionId,
      seqno: 0,
    });

    ws.send(gBBytes); // respond with g_b
    console.log("🔐 Auth key established");
  });

  ws.on("message", (data) => {
    if (!clients.has(ws)) return;

    const client = clients.get(ws);
    const { authKey, authKeyId, serverSalt, sessionId } = client;

    const buf = Buffer.from(data);
    const msgKey = buf.subarray(8, 24);
    const ciphertext = buf.subarray(24);

    // 🔓 Decrypt incoming message from client
    const { aesKey, aesIV } = deriveAESKeyAndIV(authKey, msgKey, false);
    const plaintext = aesIgeDecrypt(ciphertext, aesKey, aesIV);

    // Extract TL header from client message
    const clientSalt = plaintext.subarray(0, 8);
    const clientSession = plaintext.subarray(8, 16);
    const clientMsgId = plaintext.subarray(16, 24);
    const clientSeqNo = plaintext.subarray(24, 28);
    const messageBody = plaintext.subarray(32);

    const clientText = messageBody
      .toString("utf-8")
      .replace(/[\u0000-\u001F\u007F-\uFFFF]+$/g, "");
    console.log("📩 Client says:", clientText);

    // 🔁 Construct TL-structured reply
    const replyText = Buffer.from(`You said: ${clientText}`, "utf-8");
    const msgId = generateMsgId();
    const seqno = client.seqno;
    client.seqno += 2;

    const header = Buffer.alloc(32);
    serverSalt.copy(header, 0); // 0–7
    sessionId.copy(header, 8); // 8–15
    header.writeBigUInt64LE(msgId, 16); // 16–23
    header.writeUInt32LE(seqno, 24); // 24–27

    const fullPlaintext = Buffer.concat([header, replyText]);
    const replyMsgKey = computeMsgKey(authKey, fullPlaintext);
    const { aesKey: aesKeyResp, aesIV: aesIVResp } = deriveAESKeyAndIV(
      authKey,
      replyMsgKey,
      true
    );
    const encryptedReply = aesIgeEncrypt(fullPlaintext, aesKeyResp, aesIVResp);

    const frame = Buffer.concat([authKeyId, replyMsgKey, encryptedReply]);
    ws.send(frame);
  });
});
