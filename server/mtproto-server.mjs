import { WebSocketServer } from "ws";
import { randomBytes } from "crypto";
import { modPow, MODP_P, g, randomBigInt, bigintToBytes } from "./crypto/dh.js";
import { deriveAESKeyAndIV } from "./crypto/keyDerivation.js";
import { computeMsgKey } from "./crypto/msgKey.js";
import { aesIgeEncrypt, aesIgeDecrypt } from "./crypto/aesIge.js";

const clients = new Map(); // socket → { authKey, authKeyId }

const wss = new WebSocketServer({ port: 8080 }, () => {
  console.log("✅ MTProto WebSocket server running on ws://localhost:8080");
});

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

    clients.set(ws, { authKey, authKeyId });

    ws.send(gBBytes); // respond with g_b
    console.log("🔐 Auth key established");
  });

  ws.on("message", (data) => {
    if (!clients.has(ws)) return;

    const { authKey, authKeyId } = clients.get(ws);

    const buf = Buffer.from(data);
    const msgKey = buf.subarray(8, 24);
    const ciphertext = buf.subarray(24);

    const { aesKey, aesIV } = deriveAESKeyAndIV(authKey, msgKey, false);
    const plaintext = aesIgeDecrypt(ciphertext, aesKey, aesIV);
    const message = plaintext.toString("utf-8");

    console.log("📩 Client says:", message);

    // 🔁 Encrypt response
    const replyText = Buffer.from(`You said: ${message}`, "utf-8");
    const replyMsgKey = computeMsgKey(authKey, replyText);
    const { aesKey: aesKeyResp, aesIV: aesIVResp } = deriveAESKeyAndIV(
      authKey,
      replyMsgKey,
      true
    );
    const encryptedReply = aesIgeEncrypt(replyText, aesKeyResp, aesIVResp);

    const frame = Buffer.concat([authKeyId, replyMsgKey, encryptedReply]);

    ws.send(frame);
  });
});
