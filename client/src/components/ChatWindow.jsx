// src/components/ChatWindow.jsx
import { useState, useEffect, useRef } from "react";
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

// Register TL schemas (must match your tl.js)
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

export default function ChatWindow() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [connected, setConnected] = useState(false);
  const authKeyRef = useRef(null);
  const authKeyIdRef = useRef(null);

  // Prompt for your own userId
  const storedUser = localStorage.getItem("userId");
  const [userId, setUserId] = useState(storedUser ? Number(storedUser) : null);
  useEffect(() => {
    if (userId == null) {
      const id = Number(prompt("Enter your numeric user ID:"));
      localStorage.setItem("userId", id);
      setUserId(id);
    }
  }, [userId]);

  // Prompt for the recipient's userId
  const storedRec = localStorage.getItem("recipientId");
  const [activeContactId, setActiveContactId] = useState(
    storedRec ? Number(storedRec) : null
  );
  useEffect(() => {
    if (activeContactId == null) {
      const rid = Number(prompt("Enter the recipient's user ID:"));
      localStorage.setItem("recipientId", rid);
      setActiveContactId(rid);
    }
  }, [activeContactId]);

  useEffect(() => {
    if (userId == null || activeContactId == null) return;

    // Open raw WebSocket
    const socket = new WebSocket(`ws://localhost:8080?userId=${userId}`);
    socket.binaryType = "arraybuffer";

    // Prepare our DH share
    const a = randomBigInt();
    const g_a = modPow(g, a, MODP_P);
    const gABytes = bigintToBytes(g_a);

    // Send DH share when socket opens
    socket.onopen = () => {
      socket.send(gABytes);
    };

    // Handle incoming messages
    socket.onmessage = async (evt) => {
      const data = new Uint8Array(evt.data);

      // 1) DH response?
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

      // 2) Encrypted message
      const authKey = authKeyRef.current;
      const msgKey = data.slice(8, 24);
      const ciphertext = data.slice(24);
      const { aesKey, aesIV } = await deriveAESKeyAndIV(authKey, msgKey);
      const plaintext = await aesIgeDecrypt(ciphertext, aesKey, aesIV);

      // Peel off MTProto header (32 bytes)
      const raw = plaintext.subarray(32);
      const body = Buffer.from(raw);
      const isContainer = body.readUInt32LE(0) === 0x73f1f8dc;

      // Function to decode a single TL object buffer
      const tryDecode = (buf) => {
        try {
          const obj = decodeTLObject(Buffer.from(buf));
          if (obj._ === "message") {
            // Only show if from our selected contact
            if (Number(obj.to_user_id) === userId) {
              setMessages((prev) => [...prev, obj.text]);
            }
          } else if (obj._ === "msgs_ack") {
            console.log("✅ Received msgs_ack:", obj.msg_ids.map(String));
          }
        } catch (e) {
          console.warn("⚠️ TL decode failed:", e.message);
        }
      };

      if (!isContainer) {
        tryDecode(body);
      } else {
        const count = body.readUInt32LE(4);
        let offset = 8;
        for (let i = 0; i < count; i++) {
          const len = body.readUInt32LE(offset + 12);
          const msgBuf = body.slice(offset + 16, offset + 16 + len);
          tryDecode(msgBuf);
          offset += 16 + len;
        }
      }
    };

    socket.onclose = () => {
      setConnected(false);
      console.warn("⚠️ WebSocket closed.");
    };
    socket.onerror = (err) => {
      console.error("❌ WebSocket error:", err);
      setConnected(false);
    };

    // Expose for sendMessage()
    window._mtproto = socket;

    return () => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
    };
  }, [userId, activeContactId]);

  // Generate a MTProto‐style message ID
  function generateMsgId() {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const millis = BigInt(Date.now() % 1000);
    const rand = BigInt(Math.floor(Math.random() * 4));
    return (now << 32n) | (millis << 22n) | (rand << 2n);
  }

  // Send button handler
  const sendMessage = async () => {
    const socket = window._mtproto;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      console.warn("🛑 WebSocket not open");
      return;
    }
    const authKey = authKeyRef.current;
    const authKeyId = authKeyIdRef.current;

    // TL encode
    const tlPayload = encodeTLObject({
      _: "message",
      to_user_id: BigInt(activeContactId),
      text: input,
    });

    // Inner header (16 bytes)
    const innerHdr = Buffer.alloc(16);
    innerHdr.writeBigUInt64LE(generateMsgId(), 0);
    innerHdr.writeUInt32LE(1, 8); // seqno
    innerHdr.writeUInt32LE(tlPayload.length, 12);

    const innerMsg = Buffer.concat([innerHdr, tlPayload]);

    // Container wrapper (8 bytes)
    const containerHdr = Buffer.alloc(8);
    containerHdr.writeUInt32LE(0x73f1f8dc, 0);
    containerHdr.writeUInt32LE(1, 4);
    const container = Buffer.concat([containerHdr, innerMsg]);

    // Prepend 32 zero bytes (MTProto header placeholder)
    const fullPlain = Buffer.concat([Buffer.alloc(32), container]);

    // Compute msg_key & encrypt
    const msgKey = await computeMsgKey(authKey, fullPlain);
    const { aesKey, aesIV } = await deriveAESKeyAndIV(authKey, msgKey);
    const encrypted = await aesIgeEncrypt(fullPlain, aesKey, aesIV);

    // Final payload: auth_key_id | msg_key | ciphertext
    const payload = Buffer.concat([authKeyId, msgKey, encrypted]);

    console.log("📤 Sending to", activeContactId, ":", input);
    socket.send(payload);
    setInput("");
  };

  return (
    <div>
      <textarea
        readOnly
        value={messages.join("\n")}
        style={{ width: "100%", height: 300 }}
      />
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Type a message…"
      />
      <button onClick={sendMessage} disabled={!connected}>
        Send
      </button>
    </div>
  );
}
