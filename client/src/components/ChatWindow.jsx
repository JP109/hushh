import { useState, useEffect } from "react";
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

  useEffect(() => {
    const socket = new MTProtoSocket("ws://localhost:8080");
    const a = randomBigInt();
    const g_a = modPow(g, a, MODP_P);
    const gABytes = bigintToBytes(g_a);

    socket.connect(() => {
      socket.send(gABytes);
    });

    socket.setOnMessage(async (data) => {
      if (!authKey) {
        // First message = g_b
        const g_b = bytesToBigInt(data);
        const g_ab = modPow(g_b, a, MODP_P);
        const shared = bigintToBytes(g_ab, 256);
        setAuthKey(shared);
        setAuthKeyId(shared.slice(-8));
        return;
      }

      const msgKey = data.slice(8, 24);
      const encrypted = data.slice(24);
      const { aesKey, aesIV } = await deriveAESKeyAndIV(authKey, msgKey);
      const decrypted = await aesIgeDecrypt(encrypted, aesKey, aesIV);
      setMessages((msgs) => [...msgs, new TextDecoder().decode(decrypted)]);
    });

    window._mtproto = socket;
  }, []);

  const sendMessage = async () => {
    const socket = window._mtproto;
    const plaintext = new TextEncoder().encode(input);
    const msgKey = await computeMsgKey(authKey, plaintext);
    const { aesKey, aesIV } = await deriveAESKeyAndIV(authKey, msgKey);
    const encrypted = await aesIgeEncrypt(plaintext, aesKey, aesIV);
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
