import { useState, useEffect, useRef } from "react";
import MTProtoSocket from "../net/mtprotoSocket";
import { register, encodeTLObject, decodeTLObject } from "../tl/tl.js";
import {
  modPow,
  MODP_P,
  g,
  randomBigInt,
  bigintToBytes,
  bytesToBigInt,
} from "../crypto/dh";
import { computeMsgKey } from "../crypto/msgKey";
import { deriveAESKeyAndIV } from "../crypto/keyDerivation";
import { aesIgeEncrypt, aesIgeDecrypt } from "../crypto/aesIge";
import { Buffer } from "buffer";
window.Buffer = Buffer;

// Register TL schemas
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

export default function ChatWindow() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [connected, setConnected] = useState(false);
  const authKeyRef = useRef(null);
  const authKeyIdRef = useRef(null);

  useEffect(() => {
    const socket = new MTProtoSocket("ws://localhost:8080");
    const a = randomBigInt();
    const g_a = modPow(g, a, MODP_P);
    const gABytes = bigintToBytes(g_a);

    socket.connect(() => {
      socket.send(gABytes);
    });

    socket.setOnMessage(async (data) => {
      if (!authKeyRef.current) {
        const g_b = bytesToBigInt(data);
        const g_ab = modPow(g_b, a, MODP_P);
        const authKey = bigintToBytes(g_ab, 256);
        authKeyRef.current = authKey;
        authKeyIdRef.current = authKey.slice(-8);
        setConnected(true);
        console.log("✅ Auth key established");
        return;
      }

      const authKey = authKeyRef.current;
      const msgKey = data.slice(8, 24);
      const ciphertext = data.slice(24);
      const { aesKey, aesIV } = await deriveAESKeyAndIV(authKey, msgKey);
      const plaintext = await aesIgeDecrypt(ciphertext, aesKey, aesIV);
      const body = plaintext.subarray(32);

      const containerConstructor = Buffer.from(body).readUInt32LE(0);
      if (containerConstructor !== 0x73f1f8dc) {
        try {
          const decoded = decodeTLObject(Buffer.from(body));
          if (decoded._ === "message") {
            setMessages((prev) => [...prev, decoded.text]);
          } else if (decoded._ === "msgs_ack") {
            console.log(
              "✅ Received msgs_ack for:",
              decoded.msg_ids.map(String)
            );
          } else {
            console.warn("⚠️ Ignored TL object:", decoded._);
          }
        } catch (e) {
          console.warn("⚠️ Could not decode TL object:", e);
        }
        return;
      }

      const decodedMessages = [];
      const count = Buffer.from(body).readUInt32LE(4);
      let offset = 8;

      for (let i = 0; i < count; i++) {
        const bytes = Buffer.from(body).readUInt32LE(offset + 12);
        const msgBody = body.slice(offset + 16, offset + 16 + bytes);
        try {
          const decoded = decodeTLObject(Buffer.from(msgBody));
          console.log("📦 Inner decoded:", decoded);
          if (decoded._ === "message") {
            decodedMessages.push(decoded.text);
          }
        } catch (err) {
          console.warn("⚠️ Could not decode TL inner object:", err);
        }
        offset += 16 + bytes;
      }

      if (decodedMessages.length > 0) {
        setMessages((prev) => [...prev, ...decodedMessages]);
      }
    });

    socket.setOnClose(() => {
      setConnected(false);
      window._mtproto = null;
      console.warn("⚠️ WebSocket closed.");
    });

    socket.setOnError((err) => {
      console.error("❌ WebSocket error:", err);
      setConnected(false);
      window._mtproto = null;
    });

    window._mtproto = socket;

    return () => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
    };
  }, []);

  function generateMsgId() {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const millis = BigInt(Date.now() % 1000);
    const random = BigInt(Math.floor(Math.random() * 4));
    return (now << 32n) | (millis << 22n) | (random << 2n);
  }

  const sendMessage = async () => {
    const socket = window._mtproto;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      console.warn("🛑 WebSocket not open");
      return;
    }

    const tlPayload = encodeTLObject({ _: "message", text: input });
    const innerHeader = Buffer.alloc(16);
    const innerMsgId = generateMsgId();
    innerHeader.writeBigUInt64LE(innerMsgId, 0);
    innerHeader.writeUInt32LE(1, 8); // seqno
    innerHeader.writeUInt32LE(tlPayload.length, 12);
    const innerMessage = Buffer.concat([innerHeader, tlPayload]);

    const containerHeader = Buffer.alloc(8);
    containerHeader.writeUInt32LE(0x73f1f8dc, 0);
    containerHeader.writeUInt32LE(1, 4);
    const container = Buffer.concat([containerHeader, innerMessage]);

    const fullPlaintext = Buffer.concat([Buffer.alloc(32), container]);
    const msgKey = await computeMsgKey(authKeyRef.current, fullPlaintext);
    const { aesKey, aesIV } = await deriveAESKeyAndIV(
      authKeyRef.current,
      msgKey
    );
    const encrypted = await aesIgeEncrypt(fullPlaintext, aesKey, aesIV);
    const payload = Buffer.concat([authKeyIdRef.current, msgKey, encrypted]);

    console.log("📤 Sending TL object:", { _: "message", text: input });
    console.log("🔐 Encrypted payload:", payload.toString("hex"));
    socket.send(payload);
    setInput("");
  };

  return (
    <div>
      <textarea
        readOnly
        value={messages.join("\n")}
        style={{ width: "100%", height: "300px" }}
      />
      <input value={input} onChange={(e) => setInput(e.target.value)} />
      <button onClick={sendMessage} disabled={!connected}>
        Send
      </button>
    </div>
  );
}
