import { WebSocketServer } from "ws";
import { randomBytes } from "crypto";
import { modPow, MODP_P, g, randomBigInt, bigintToBytes } from "./crypto/dh.js";

const clients = new Map();

const wss = new WebSocketServer({ port: 8080 }, () => {
  console.log("✅ MTProto WebSocket server running on ws://localhost:8080");
});

wss.on("connection", (ws) => {
  console.log("🔌 Client connected");

  ws.on("message", (msg) => {
    const data = Buffer.from(msg);
    console.log("📩 Received:", data.toString("hex"));
    // Add decryption, msg_key checks here later
  });

  ws.send("💬 Welcome to MTProto test server");
});
