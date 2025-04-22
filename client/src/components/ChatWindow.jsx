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
      //   console.log("AAAA", data);
      if (!authKeyRef.current) {
        // First message = g_b
        const g_b = bytesToBigInt(data);
        const g_ab = modPow(g_b, a, MODP_P);
        const shared = bigintToBytes(g_ab, 256);
        setAuthKey(shared);
        setAuthKeyId(shared.slice(-8));
        authKeyRef.current = shared; // ✅ set ref
        return;
      }

      const msgKey = data.slice(8, 24);
      const encrypted = data.slice(24);
      const { aesKey, aesIV } = await deriveAESKeyAndIV(
        authKeyRef.current,
        msgKey
      );
      const decrypted = await aesIgeDecrypt(encrypted, aesKey, aesIV);

      // strip TL header (32 bytes)
      const serverSalt = decrypted.slice(0, 8);
      const sessionId = decrypted.slice(8, 16);
      const msgId = decrypted.slice(16, 24);
      const seqno = decrypted.slice(24, 28);
      const message = decrypted.slice(32);

      const clean = new TextDecoder()
        .decode(message)
        .replace(/[\u0000-\u001F\u007F-\uFFFF]+$/g, "");
      setMessages((msgs) => [...msgs, clean]);
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
