import { useEffect, useState } from "react";
import MTProtoSocket from "../net/mtprotoSocket";

export default function ChatWindow() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");

  useEffect(() => {
    const socket = new MTProtoSocket("ws://localhost:8080");
    socket.connect();

    socket.onMessage = (data) => {
      setMessages((msgs) => [...msgs, new TextDecoder().decode(data)]);
    };

    window._mtprotoSocket = socket;
  }, []);

  const sendMsg = () => {
    const encoded = new TextEncoder().encode(input);
    window._mtprotoSocket.send(encoded);
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
      <button onClick={sendMsg}>Send</button>
    </div>
  );
}
