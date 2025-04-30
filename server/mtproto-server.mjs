// server/mtproto-server.mjs

import { WebSocketServer } from "ws";
import { randomBytes } from "crypto";
import { modPow, MODP_P, g, randomBigInt, bigintToBytes } from "./crypto/dh.js";
import { deriveAESKeyAndIV } from "./crypto/keyDerivation.js";
import { computeMsgKey } from "./crypto/msgKey.js";
import { aesIgeEncrypt, aesIgeDecrypt } from "./crypto/aesIge.js";
import {
  register,
  decodeTLObject,
  encodeTLObject,
  tlRegistry,
} from "./tl/tl.js";

// ─── Register constructors ─────────────────────────────────────────────────────
register({
  id: 0x5c4d7a1f,
  name: "message",
  args: [{ name: "text", type: "string" }],
});
register({
  id: 0xddf60e02,
  name: "msgs_ack",
  args: [{ name: "msg_ids", type: "Vector<long>" }],
});

console.log("📚 Registered constructors:", [...tlRegistry.entries()]);

// ─── State for all clients ────────────────────────────────────────────────────
// Map<WebSocket, { authKey, authKeyId, serverSalt, sessionId, seqno }>
const clients = new Map();

const wss = new WebSocketServer({ port: 8080 }, () => {
  console.log("✅ MTProto WebSocket server running on ws://localhost:8080");
});

function generateMsgId() {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const millis = BigInt(Date.now() % 1000);
  const random = BigInt(Math.floor(Math.random() * 4));
  return (now << 32n) | (millis << 22n) | (random << 2n);
}

wss.on("connection", (ws) => {
  console.log("🔌 Client connected");

  // → STEP 1: Diffie–Hellman handshake
  let serverPriv = randomBigInt();
  let g_b = modPow(g, serverPriv, MODP_P);
  let gBBytes = bigintToBytes(g_b);
  ws.send(gBBytes);

  // → STEP 2: receive client's share, derive auth_key & store state
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

  // → STEP 3: handle all encrypted messages
  ws.on("message", (data) => {
    if (!clients.has(ws)) return;
    const client = clients.get(ws);
    const { authKey, authKeyId, serverSalt, sessionId } = client;

    // MTProto envelope: [ authKeyId(8) | msgKey(16) | ciphertext(...) ]
    const msgKey = data.subarray(8, 24);
    const ciphertext = data.subarray(24);

    // decrypt
    const { aesKey, aesIV } = deriveAESKeyAndIV(authKey, msgKey, false);
    const plaintext = aesIgeDecrypt(ciphertext, aesKey, aesIV);

    // strip your 32-byte prefix, then parse container
    const body = plaintext.subarray(32);
    const containerId = body.readUInt32LE(0);

    // if it's not a container, try decoding directly
    if (containerId !== 0x73f1f8dc) {
      try {
        const decoded = decodeTLObject(body);
        if (decoded._ === "message") {
          console.log("💬 Client says:", decoded.text);
          broadcast(decoded.text, ws);
        }
      } catch {
        console.warn("⚠️ Could not decode TL object outside container");
      }
      return;
    }

    // it _is_ a container: iterate inner messages
    const count = body.readUInt32LE(4);
    let offset = 8;
    for (let i = 0; i < count; i++) {
      const length = body.readUInt32LE(offset + 12);
      const inner = body.subarray(offset + 16, offset + 16 + length);
      const decoded = decodeTLObject(inner);

      if (decoded._ === "message") {
        console.log("💬 Client says:", decoded.text);
        broadcast(decoded.text, ws);
      }
      offset += 16 + length;
    }
  });

  ws.on("close", () => {
    clients.delete(ws);
    console.log("❌ Client disconnected");
  });
});

/**
 * Broadcast a text‐message to all other clients
 */
function broadcast(text, senderWs) {
  for (const [otherWs, other] of clients.entries()) {
    if (otherWs === senderWs || otherWs.readyState !== otherWs.OPEN) continue;

    // build the reply TL
    const replyBody = encodeTLObject({
      _: "message",
      text: `🟢 ${text}`,
    });

    // inner message header
    const innerMsgId = generateMsgId();
    const innerHeader = Buffer.alloc(16);
    innerHeader.writeBigUInt64LE(innerMsgId, 0);
    innerHeader.writeUInt32LE(other.seqno, 8);
    other.seqno += 2;
    innerHeader.writeUInt32LE(replyBody.length, 12);
    const innerMsg = Buffer.concat([innerHeader, replyBody]);

    // container wrapper (1 message)
    const containerHeader = Buffer.alloc(8);
    containerHeader.writeUInt32LE(0x73f1f8dc, 0);
    containerHeader.writeUInt32LE(1, 4);
    const container = Buffer.concat([containerHeader, innerMsg]);

    // full MTProto header (32 bytes)
    const header = Buffer.alloc(32);
    other.serverSalt.copy(header, 0);
    other.sessionId.copy(header, 8);
    header.writeBigUInt64LE(generateMsgId(), 16);
    header.writeUInt32LE(other.seqno, 24);
    other.seqno += 2;

    // encrypt & send
    const fullMsg = Buffer.concat([header, container]);
    const replyMsgKey = computeMsgKey(other.authKey, fullMsg);
    const { aesKey: respKey, aesIV: respIV } = deriveAESKeyAndIV(
      other.authKey,
      replyMsgKey,
      true
    );
    const encrypted = aesIgeEncrypt(fullMsg, respKey, respIV);
    const payload = Buffer.concat([other.authKeyId, replyMsgKey, encrypted]);

    otherWs.send(payload);
  }
}
