// src/components/ChatWindow.jsx
import React, { useState, useEffect, useRef } from "react";
import { register, encodeTLObject, decodeTLObject } from "../tl/tl.js";
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
  const [mode, setMode] = useState("login"); // "login" | "signup" | "chat"
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

  // Keep the ref in sync whenever the state changes
  useEffect(() => {
    activeContactRef.current = activeContactId;
  }, [activeContactId]);

  // If we already have token+user, go straight to chat
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
    if (mode !== "chat") return;
    if (!user || !token) return;

    // // Prompt for a contact ID if not set
    // let rid = activeContactId || Number(prompt("Enter recipient user ID:"));
    // setActiveContactId(rid);

    // Fetch list of all users, then prompt via UI
    fetch("http://localhost:3001/users", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.json())
      .then((list) => {
        // remove yourself from the list
        setContacts(list.filter((u) => u.id !== user.id));
      })
      .catch(console.error);

    // Decide if we can resume (have an authKey stored)
    const storedKey = localStorage.getItem("authKey");
    const storedKeyId = localStorage.getItem("authKeyId");
    const resume = !!storedKey && !!storedKeyId;

    // Open WS with both userId and token+resume flags
    const socket = new WebSocket(
      `ws://localhost:8080?userId=${user.id}&token=${token}&resume=${resume}`
    );
    socket.binaryType = "arraybuffer";

    // Prepare our DH share in case we do a fresh handshake
    const a = randomBigInt();
    const gA = modPow(g, a, MODP_P);
    const gABytes = bigintToBytes(gA);

    socket.onopen = () => {
      if (!resume) {
        // send DH share to server
        socket.send(gABytes);
      } else {
        // rehydrate keys from localStorage
        authKeyRef.current = Buffer.from(storedKey, "base64");
        authKeyIdRef.current = Buffer.from(storedKeyId, "hex");
        setConnected(true);
        console.log("🔄 Resumed session");
      }
    };

    socket.onmessage = async (evt) => {
      const data = new Uint8Array(evt.data);

      // 1) If no authKey yet, this is the server's g^b
      if (!authKeyRef.current) {
        const gB = bytesToBigInt(data);
        const g_ab = modPow(gB, a, MODP_P);
        const authKey = bigintToBytes(g_ab, 256);
        authKeyRef.current = authKey;
        authKeyIdRef.current = authKey.slice(-8);
        // persist for future resumes
        localStorage.setItem(
          "authKey",
          Buffer.from(authKey).toString("base64")
        );
        localStorage.setItem(
          "authKeyId",
          Buffer.from(authKey.slice(-8)).toString("hex")
        );
        setConnected(true);
        console.log("✅ Auth key established");
        return;
      }

      // 2) Otherwise decrypt an MTProto message
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

      // for (const raw of parts) {
      //   const buf = Buffer.from(raw);
      //   if (buf.readUInt32LE(0) !== 0x5c4d7a1f) continue;
      //   const msg = decodeTLObject(buf);
      //   // show every message whose to_user_id === me,
      //   // prefixing with the sender’s ID/email
      //   if (Number(msg.to_user_id) === user.id) {
      //     setMessages((m) => [
      //       ...m,
      //       `From ${msg.from_user_id === user.id ? "You" : msg.from_user_id}: ${
      //         msg.text
      //       }`,
      //     ]);
      //   }
      // }
    };

    socket.onclose = () => {
      setConnected(false);
      console.warn("⚠️ WebSocket closed");
    };
    socket.onerror = (err) => {
      console.error("❌ WS error", err);
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

  // --- RENDER UI ---
  if (mode === "login" || mode === "signup") {
    return (
      <div style={{ padding: 20 }}>
        <h2>{mode === "login" ? "Log In" : "Sign Up"}</h2>
        <input
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <br />
        <input
          placeholder="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <br />
        <button onClick={mode === "login" ? login : signup}>
          {mode === "login" ? "Log In" : "Sign Up"}
        </button>
        <p onClick={() => setMode(mode === "login" ? "signup" : "login")}>
          {mode === "login" ? "Need an account?" : "Have an account?"}
        </p>
      </div>
    );
  }

  return (
    <div style={{ padding: 20 }}>
      <div style={{ padding: 20 }}>
        <h3>Select a contact to chat with:</h3>
        <ul>
          {contacts.map((c) => (
            <li key={c.id}>
              <button onClick={() => setActiveContactId(c.id)}>
                {c.email} (ID: {c.id})
              </button>
            </li>
          ))}
        </ul>
      </div>
      <h3>Chat with User {activeContactId}</h3>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 10,
        }}
      >
        <h3>Chat with User {activeContactId}</h3>
        <div style={{ textAlign: "right" }}>
          <div>
            <strong>{user.email}</strong> (ID {user.id})
          </div>
          <button onClick={logout}>Logout</button>
        </div>
      </div>
      <div
        style={{
          border: "1px solid #ccc",
          height: 300,
          overflowY: "scroll",
          padding: 10,
          marginBottom: 10,
        }}
      >
        {messages.map((m, i) => (
          <div key={i}>{m}</div>
        ))}
      </div>
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        style={{ width: "80%" }}
      />
      <button onClick={sendMessage} disabled={!connected}>
        Send
      </button>
    </div>
  );
}
