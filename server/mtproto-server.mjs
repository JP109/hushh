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

    const { aesKey, aesIV } = deriveAESKeyAndIV(authKey, msgKey, false);
    const plaintext = aesIgeDecrypt(ciphertext, aesKey, aesIV);

    const clientMsgId = plaintext.readBigUInt64LE(16);

    const clientText = plaintext
      .subarray(32)
      .toString("utf-8")
      .replace(/[\u0000-\u001F\u007F-\uFFFF]+$/g, "");
    console.log("📩 Client says:", clientText);

    // Create reply message
    const replyBody = Buffer.from(`You said: ${clientText}`, "utf-8");
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

    // ✅ Send msgs_ack
    const ackMsgId = generateMsgId();
    const ackSeqno = client.seqno;
    client.seqno += 2;

    const ackConstructor = Buffer.from("59b4d662", "hex").reverse(); // #62d6b459
    const vectorConstructor = Buffer.from("1cb5c415", "hex").reverse();
    const ackCount = Buffer.alloc(4);
    ackCount.writeUInt32LE(1, 0);
    const ackMsgIdBuf = Buffer.alloc(8);
    ackMsgIdBuf.writeBigUInt64LE(clientMsgId);

    const ackBody = Buffer.concat([
      ackConstructor,
      vectorConstructor,
      ackCount,
      ackMsgIdBuf,
    ]);

    const ackHeader = Buffer.alloc(16);
    ackHeader.writeBigUInt64LE(ackMsgId, 0);
    ackHeader.writeUInt32LE(ackSeqno, 8);
    ackHeader.writeUInt32LE(ackBody.length, 12);
    const ackMessage = Buffer.concat([ackHeader, ackBody]);

    const ackContainer = Buffer.concat([
      containerConstructor,
      count,
      ackMessage,
    ]);

    const ackOuterMsgId = generateMsgId();
    const ackOuterSeqno = client.seqno;
    client.seqno += 2;

    const ackOuterHeader = Buffer.alloc(32);
    serverSalt.copy(ackOuterHeader, 0);
    sessionId.copy(ackOuterHeader, 8);
    ackOuterHeader.writeBigUInt64LE(ackOuterMsgId, 16);
    ackOuterHeader.writeUInt32LE(ackOuterSeqno, 24);

    const ackPlaintext = Buffer.concat([ackOuterHeader, ackContainer]);
    const ackMsgKey = computeMsgKey(authKey, ackPlaintext);
    const { aesKey: ackKey, aesIV: ackIV } = deriveAESKeyAndIV(
      authKey,
      ackMsgKey,
      true
    );
    const encryptedAck = aesIgeEncrypt(ackPlaintext, ackKey, ackIV);
    ws.send(Buffer.concat([authKeyId, ackMsgKey, encryptedAck]));
  });
});
