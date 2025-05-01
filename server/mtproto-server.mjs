/* server/mtproto-server.mjs */
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
  args: [
    { name: "to_user_id", type: "long" },
    { name: "text", type: "string" },
  ],
});
register({
  id: 0xddf60e02,
  name: "msgs_ack",
  args: [{ name: "msg_ids", type: "Vector<long>" }],
});

const clients = new Map();
const clientsByUserId = new Map();

function generateMsgId() {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const millis = BigInt(Date.now() % 1000);
  const rand = BigInt(Math.floor(Math.random() * 4));
  return (now << 32n) | (millis << 22n) | (rand << 2n);
}

const wss = new WebSocketServer({ port: 8080 }, () => {
  console.log("✅ MTProto WebSocket server running on ws://localhost:8080");
});

wss.on("connection", (ws, req) => {
  const params = new URL(req.url, `ws://${req.headers.host}`).searchParams;
  const userId = Number(params.get("userId"));
  console.log("🔌 Client connected, userId =", userId);

  const serverPriv = randomBigInt();
  const gB = modPow(g, serverPriv, MODP_P);
  ws.send(bigintToBytes(gB));

  ws.once("message", (msg) => {
    const gA = BigInt("0x" + Buffer.from(msg).toString("hex"));
    const g_ab = modPow(gA, serverPriv, MODP_P);
    const authKey = bigintToBytes(g_ab, 256);
    const authKeyId = authKey.subarray(256 - 8);
    const serverSalt = randomBytes(8);
    const sessionId = randomBytes(8);

    const state = {
      userId,
      authKey,
      authKeyId,
      serverSalt,
      sessionId,
      seqno: 0,
    };
    clients.set(ws, state);
    clientsByUserId.set(userId, ws);
    console.log("🔐 Auth key established for user", userId);
  });

  ws.on("message", (data) => {
    const client = clients.get(ws);
    if (!client) return;
    const { authKey } = client;
    const msgKey = data.slice(8, 24);
    const ciphertext = data.slice(24);
    const { aesKey, aesIV } = deriveAESKeyAndIV(authKey, msgKey, false);
    const decrypted = aesIgeDecrypt(ciphertext, aesKey, aesIV);

    const body = decrypted.slice(32);
    const isContainer = body.readUInt32LE(0) === 0x73f1f8dc;
    const segments = [];
    if (isContainer) {
      const count = body.readUInt32LE(4);
      let off = 8;
      for (let i = 0; i < count; i++) {
        const len = body.readUInt32LE(off + 12);
        segments.push(body.slice(off + 16, off + 16 + len));
        off += 16 + len;
      }
    } else segments.push(body);

    for (const seg of segments) {
      if (seg.readUInt32LE(0) !== 0x5c4d7a1f) continue;
      const { to_user_id, text } = decodeTLObject(seg);
      const destWs = clientsByUserId.get(Number(to_user_id));
      if (destWs && destWs.readyState === destWs.OPEN) {
        sendToOne(clients.get(destWs), destWs, {
          _: "message",
          to_user_id,
          text,
        });
      }
    }
  });

  ws.on("close", () => {
    const st = clients.get(ws);
    if (st) clientsByUserId.delete(st.userId);
    clients.delete(ws);
    console.log("❌ Client disconnected:", st?.userId);
  });
});

function sendToOne(destClient, destWs, msgObj) {
  const body = encodeTLObject(msgObj);
  const innerHdr = Buffer.alloc(16);
  innerHdr.writeBigUInt64LE(generateMsgId(), 0);
  innerHdr.writeUInt32LE(destClient.seqno, 8);
  destClient.seqno += 2;
  innerHdr.writeUInt32LE(body.length, 12);
  const innerMsg = Buffer.concat([innerHdr, body]);

  const containerHdr = Buffer.alloc(8);
  containerHdr.writeUInt32LE(0x73f1f8dc, 0);
  containerHdr.writeUInt32LE(1, 4);
  const container = Buffer.concat([containerHdr, innerMsg]);

  const hdr = Buffer.alloc(32);
  destClient.serverSalt.copy(hdr, 0);
  destClient.sessionId.copy(hdr, 8);
  hdr.writeBigUInt64LE(generateMsgId(), 16);
  hdr.writeUInt32LE(destClient.seqno, 24);
  destClient.seqno += 2;

  const full = Buffer.concat([hdr, container]);
  const msgKey = computeMsgKey(destClient.authKey, full);
  const { aesKey, aesIV } = deriveAESKeyAndIV(destClient.authKey, msgKey, true);
  const encrypted = aesIgeEncrypt(full, aesKey, aesIV);

  destWs.send(Buffer.concat([destClient.authKeyId, msgKey, encrypted]));
}
