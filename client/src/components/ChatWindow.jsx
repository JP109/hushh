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
  const [connected, setConnected] = useState(false); // ✅ connection state
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
      if (!authKeyRef.current) {
        const g_b = bytesToBigInt(data);
        const g_ab = modPow(g_b, a, MODP_P);
        const shared = bigintToBytes(g_ab, 256);
        setAuthKey(shared);
        setAuthKeyId(shared.slice(-8));
        authKeyRef.current = shared;
        setConnected(true); // ✅ enable Send button
        console.log("✅ Auth key established");
        return;
      }

      const authKey = authKeyRef.current;
      const msgKey = data.slice(8, 24);
      const encrypted = data.slice(24);

      const { aesKey, aesIV } = await deriveAESKeyAndIV(authKey, msgKey);
      const decrypted = await aesIgeDecrypt(encrypted, aesKey, aesIV);

      const tlBody = decrypted.subarray(32); // cleaner alias
      const constructorId =
        (tlBody[0] |
          (tlBody[1] << 8) |
          (tlBody[2] << 16) |
          (tlBody[3] << 24)) >>>
        0;

      if (constructorId !== 0x73f1f8dc) {
        // Not a container – treat as a standalone message
        const typeId = tlBody.slice(0, 4).reverse().toString("hex");
        if (typeId === "62d6b459") {
          const ackCount = new DataView(
            tlBody.buffer,
            tlBody.byteOffset + 8
          ).getUint32(0, true);
          const ackIds = [];
          for (let j = 0; j < ackCount; j++) {
            const ackMsgId = new DataView(
              tlBody.buffer,
              tlBody.byteOffset + 12 + j * 8
            ).getBigUint64(0, true);
            ackIds.push(ackMsgId.toString());
          }
          console.log("✅ Received single msgs_ack for:", ackIds);
        } else {
          const text = new TextDecoder()
            .decode(tlBody)
            .replace(/[\u0000-\u001F\u007F-\uFFFF]+$/g, "");
          setMessages((prev) => [...prev, text]);
        }
        return;
      }

      const count = new DataView(tlBody.buffer, tlBody.byteOffset).getUint32(
        4,
        true
      );
      let offset = 8;
      const messages = [];

      for (let i = 0; i < count; i++) {
        const msgId = new DataView(
          tlBody.buffer,
          tlBody.byteOffset + offset
        ).getBigUint64(0, true);

        const seqno = new DataView(
          tlBody.buffer,
          tlBody.byteOffset + offset + 8
        ).getUint32(0, true);
        const bytes = new DataView(
          tlBody.buffer,
          tlBody.byteOffset + offset + 12
        ).getUint32(0, true);

        const body = tlBody.slice(offset + 16, offset + 16 + bytes);

        const typeId = body.slice(0, 4).reverse().toString("hex");
        if (typeId === "62d6b459") {
          const ackCount = new DataView(
            body.buffer,
            body.byteOffset + 8
          ).getUint32(0, true);

          const ackIds = [];
          for (let j = 0; j < ackCount; j++) {
            const ackOffset = 12 + j * 8;
            const ackMsgId = new DataView(
              body.buffer,
              body.byteOffset + 12 + j * 8
            ).getBigUint64(0, true);
            ackIds.push(ackMsgId.toString());
          }
          console.log("✅ Received msgs_ack for:", ackIds);
        } else {
          const text = new TextDecoder()
            .decode(body)
            .replace(/[\u0000-\u001F\u007F-\uFFFF]+$/g, "");
          messages.push(text);
        }

        offset += 16 + bytes;
      }

      if (messages.length > 0) {
        setMessages((prev) => [...prev, ...messages]);
      }
    });

    window._mtproto = socket;
  }, []);

  const sendMessage = async () => {
    const socket = window._mtproto;
    const text = new TextEncoder().encode(input);

    const header = new Uint8Array(32);
    const fullMessage = new Uint8Array(header.length + text.length);
    fullMessage.set(header);
    fullMessage.set(text, 32);

    const msgKey = await computeMsgKey(authKeyRef.current, fullMessage);
    const { aesKey, aesIV } = await deriveAESKeyAndIV(
      authKeyRef.current,
      msgKey
    );
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
      <button onClick={sendMessage} disabled={!connected}>
        Send
      </button>
    </div>
  );
}
