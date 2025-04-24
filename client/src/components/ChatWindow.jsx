import { useState, useEffect, useRef } from "react";
import MTProtoSocket from "../net/mtprotoSocket";
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

export default function ChatWindow() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [authKey, setAuthKey] = useState(null);
  const [authKeyId, setAuthKeyId] = useState(null);
  const authKeyRef = useRef(null);

  useEffect(() => {
    const socket = new MTProtoSocket("ws://localhost:8080");
    const a = randomBigInt();
    const g_a = modPow(g, a, MODP_P);
    const gABytes = bigintToBytes(g_a);

    socket.connect(() => {
      socket.send(gABytes);
    });

    socket.setOnMessage(async (data) => {
      const authKey = authKeyRef.current;
      if (!authKey) return;

      const msgKey = data.slice(8, 24);
      const encrypted = data.slice(24);

      const { aesKey, aesIV } = await deriveAESKeyAndIV(authKey, msgKey);
      const decrypted = await aesIgeDecrypt(encrypted, aesKey, aesIV);

      // Strip outer TL header
      const tlBody = decrypted.slice(32);

      // Check constructor ID for msg_container
      const constructor = tlBody.slice(0, 4).reverse().toString("hex");
      if (constructor !== "73f1f8dc") {
        console.error("❌ Not a msg_container:", constructor);
        return;
      }

      const count = new DataView(tlBody.buffer).getUint32(4, true); // should be 1
      const offset = 8;

      const messages = [];

      for (let i = 0; i < count; i++) {
        const msgId = tlBody.slice(offset + 0, offset + 8);
        const seqno = new DataView(tlBody.buffer).getUint32(offset + 8, true);
        const bytes = new DataView(tlBody.buffer).getUint32(offset + 12, true);
        const body = tlBody.slice(offset + 16, offset + 16 + bytes);

        const text = new TextDecoder()
          .decode(body)
          .replace(/[\u0000-\u001F\u007F-\uFFFF]+$/g, "");
        messages.push(text);

        // advance offset
        offset += 16 + bytes;
      }

      setMessages((prev) => [...prev, ...messages]);
    });

    window._mtproto = socket;
  }, []);

  const sendMessage = async () => {
    const socket = window._mtproto;
    const text = new TextEncoder().encode(input);

    // Simulate TL header (placeholder salt/session/msg_id)
    const header = new Uint8Array(32);
    // You can leave all-zero salt/session_id/msg_id for now
    const fullMessage = new Uint8Array(header.length + text.length);
    fullMessage.set(header);
    fullMessage.set(text, 32);

    const msgKey = await computeMsgKey(authKey, fullMessage);
    const { aesKey, aesIV } = await deriveAESKeyAndIV(authKey, msgKey);
    const encrypted = await aesIgeEncrypt(fullMessage, aesKey, aesIV);
    const payload = new Uint8Array([...authKeyId, ...msgKey, ...encrypted]);

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
      <button onClick={sendMessage} disabled={!authKey}>
        Send
      </button>
    </div>
  );
}
