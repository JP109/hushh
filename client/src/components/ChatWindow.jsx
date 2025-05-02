/* src/components/ChatWindow.jsx */
import React, { useState, useEffect, useRef } from "react";
import { register, encodeTLObject, decodeTLObject } from "../tl/tl.js";
import "./ChatWindow.css";
import {
  modPow,
  MODP_P,
  g,
  randomBigInt,
  bigintToBytes,
  bytesToBigInt,
} from "../crypto/dh";
import { deriveAESKeyAndIV } from "../crypto/keyDerivation";
import { computeMsgKey } from "../crypto/msgKey";
import { aesIgeEncrypt, aesIgeDecrypt } from "../crypto/aesIge";
import { Buffer } from "buffer";
window.Buffer = Buffer;

// Register your TL constructors
register({
  id: 0x5c4d7a1f,
  name: "message",
  args: [
    { name: "from_user_id", type: "long" },
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
  // --- AUTH STATES ---
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState(localStorage.getItem("token"));
  const storedUser = localStorage.getItem("user");
  const [user, setUser] = useState(
    storedUser && storedUser !== "undefined" ? JSON.parse(storedUser) : null
  );
  const [contacts, setContacts] = useState([]);

  // --- CRYPTO STATES ---
  const authKeyRef = useRef(null);
  const authKeyIdRef = useRef(null);

  // --- CHAT STATES ---
  const [ws, setWs] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [connected, setConnected] = useState(false);
  const [activeContactId, setActiveContactId] = useState(null);
  const activeContactRef = useRef(activeContactId);
  useEffect(() => {
    activeContactRef.current = activeContactId;
  }, [activeContactId]);

  useEffect(() => {
    if (token && user) setMode("chat");
  }, [token, user]);
  // --- SIGNUP / LOGIN HANDLERS ---
  async function signup() {
    const res = await fetch("http://localhost:3001/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const { token: tk, user: u } = await res.json();
    localStorage.setItem("token", tk);
    localStorage.setItem("user", JSON.stringify(u));
    setToken(tk);
    setUser(u);
    setMode("chat");
  }

  async function login() {
    const res = await fetch("http://localhost:3001/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const { token: tk, user: u } = await res.json();
    localStorage.setItem("token", tk);
    localStorage.setItem("user", JSON.stringify(u));
    setToken(tk);
    setUser(u);
    setMode("chat");
  }

  // --- WEBSOCKET & CRYPTO HANDSHAKE ---
  useEffect(() => {
    if (mode !== "chat" || !user || !token) return;

    fetch("http://localhost:3001/users", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.json())
      .then((list) => setContacts(list.filter((u) => u.id !== user.id)))
      .catch(console.error);

    const storedKey = localStorage.getItem("authKey");
    const storedKeyId = localStorage.getItem("authKeyId");
    const resume = !!storedKey && !!storedKeyId;

    const socket = new WebSocket(
      `ws://localhost:8080?userId=${user.id}&token=${token}&resume=${resume}`
    );
    socket.binaryType = "arraybuffer";

    const a = randomBigInt();
    const gA = modPow(g, a, MODP_P);
    const gABytes = bigintToBytes(gA);

    socket.onopen = () => {
      if (!resume) {
        socket.send(gABytes);
      } else {
        authKeyRef.current = Buffer.from(storedKey, "base64");
        authKeyIdRef.current = Buffer.from(storedKeyId, "hex");
        setConnected(true);
      }
    };

    socket.onmessage = async (evt) => {
      const data = new Uint8Array(evt.data);
      if (!authKeyRef.current) {
        const gB = bytesToBigInt(data);
        const g_ab = modPow(gB, a, MODP_P);
        const authKey = bigintToBytes(g_ab, 256);
        const authKeyId = authKey.slice(-8);
        authKeyRef.current = authKey;
        authKeyIdRef.current = authKeyId;
        localStorage.setItem(
          "authKey",
          Buffer.from(authKey).toString("base64")
        );
        localStorage.setItem(
          "authKeyId",
          Buffer.from(authKeyId).toString("hex")
        );
        setConnected(true);
        return;
      }

      // Decrypting incoming MTProto
      const authKey = authKeyRef.current;
      const msgKey = data.slice(8, 24);
      const cipher = data.slice(24);
      const { aesKey, aesIV } = await deriveAESKeyAndIV(authKey, msgKey, false);
      const plain = await aesIgeDecrypt(cipher, aesKey, aesIV);

      // Peel MTProto header + optional container…
      const bodyRaw = plain.subarray(32);
      const body = Buffer.from(bodyRaw);

      // Decode and append only real messages
      const isContainer = body.readUInt32LE(0) === 0x73f1f8dc;
      const parts = [];

      if (isContainer) {
        const count = body.readUInt32LE(4);
        let offset = 8;
        for (let i = 0; i < count; i++) {
          const len = body.readUInt32LE(offset + 12);
          parts.push(body.slice(offset + 16, offset + 16 + len));
          offset += 16 + len;
        }
      } else {
        parts.push(body);
      }

      for (const raw of parts) {
        const buf = Buffer.from(raw);
        if (buf.readUInt32LE(0) !== 0x5c4d7a1f) continue;
        const msg = decodeTLObject(buf);
        // auto‐open chat with whoever first messages you
        if (!activeContactId) {
          setActiveContactId(Number(msg.from_user_id));
        }
        if (Number(msg.to_user_id) === user.id) {
          // use the ref so we always compare to the latest selected contact
          if (Number(msg.from_user_id) === activeContactRef.current) {
            setMessages((m) => [...m, `Them: ${msg.text}`]);
          }
        }
      }
    };

    socket.onclose = () => {
      setConnected(false);
    };
    socket.onerror = (err) => {
      setConnected(false);
    };

    setWs(socket);
    return () => socket.close();
  }, [mode, token, user]);

  // --- SENDING MESSAGES ---
  function generateMsgId() {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const ms = BigInt(Date.now() % 1000);
    const rnd = BigInt(Math.floor(Math.random() * 4));
    return (now << 32n) | (ms << 22n) | (rnd << 2n);
  }

  const sendMessage = async () => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const authKey = authKeyRef.current;
    const authKeyId = authKeyIdRef.current;

    // Build TL message
    const tlObj = {
      _: "message",
      from_user_id: BigInt(user.id),
      to_user_id: BigInt(activeContactId),
      text: input,
    };
    const tlBuf = encodeTLObject(tlObj);

    // Inner header + container + MTProto header as before…
    const innerHdr = Buffer.alloc(16);
    innerHdr.writeBigUInt64LE(generateMsgId(), 0);
    innerHdr.writeUInt32LE(1, 8);
    innerHdr.writeUInt32LE(tlBuf.length, 12);
    const innerMsg = Buffer.concat([innerHdr, tlBuf]);

    const containerHdr = Buffer.alloc(8);
    containerHdr.writeUInt32LE(0x73f1f8dc, 0);
    containerHdr.writeUInt32LE(1, 4);
    const container = Buffer.concat([containerHdr, innerMsg]);

    const fullPlain = Buffer.concat([Buffer.alloc(32), container]);
    const msgKey = await computeMsgKey(authKey, fullPlain);
    const { aesKey, aesIV } = await deriveAESKeyAndIV(authKey, msgKey, true);
    const cipher = await aesIgeEncrypt(fullPlain, aesKey, aesIV);

    const payload = Buffer.concat([authKeyId, msgKey, cipher]);
    ws.send(payload);
    setMessages((m) => [...m, `You: ${input}`]);
    setInput("");
  };

  // ─── Logout handler ─────────────────────────────────────────────────────────
  function logout() {
    // 1) close socket
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.close();
    }
    // 2) clear stored keys & user
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    localStorage.removeItem("authKey");
    localStorage.removeItem("authKeyId");
    // 3) reset all state
    setMode("login");
    setToken(null);
    setUser(null);
    setWs(null);
    setConnected(false);
    setMessages([]);
  }

  if (mode === "login" || mode === "signup") {
    return (
      <div className="auth-container">
        <h2 className="auth-title">
          {mode === "login" ? "Log In" : "Sign Up"}
        </h2>
        <form className="auth-form" onSubmit={(e) => e.preventDefault()}>
          <input
            className="auth-input"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <input
            className="auth-input"
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button
            className="auth-button"
            onClick={mode === "login" ? login : signup}
          >
            {mode === "login" ? "Log In" : "Sign Up"}
          </button>
        </form>
        <p
          className="auth-toggle"
          onClick={() => setMode(mode === "login" ? "signup" : "login")}
        >
          {mode === "login" ? "Need an account?" : "Have an account?"}
        </p>
      </div>
    );
  }

  return (
    <>
      <div className="user-info">
        <span className="user-email">
          <strong>{user.email}</strong> (ID {user.id})
        </span>
        <button className="logout-button" onClick={logout}>
          Logout
        </button>
      </div>
      <div className="chat-app">
        <aside className="chat-sidebar">
          <h3 className="sidebar-title">Contacts</h3>
          <ul className="contact-list">
            {contacts.map((c) => (
              <li key={c.id}>
                <button
                  className={`contact-button ${
                    c.id === activeContactId ? "active" : ""
                  }`}
                  onClick={() => setActiveContactId(c.id)}
                >
                  {c.email} (ID: {c.id})
                </button>
              </li>
            ))}
          </ul>
        </aside>

        <section className="chat-window">
          <header className="chat-header">
            <h3>Chat with User {activeContactId}</h3>
          </header>

          <div className="message-container">
            {messages.map((m, i) => (
              <div key={i} className="message">
                {m}
              </div>
            ))}
          </div>

          <footer className="chat-input-area">
            <input
              className="chat-input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Type a message..."
            />
            <button
              className="send-button"
              onClick={sendMessage}
              disabled={!connected}
            >
              Send
            </button>
          </footer>
        </section>
      </div>
    </>
  );
}
