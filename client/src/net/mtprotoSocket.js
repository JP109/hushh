export default class MTProtoSocket {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.onMessage = null;
    this.onClose = null;
    this.onError = null;
  }

  connect(onOpen) {
    this.ws = new WebSocket(this.url);
    this.ws.binaryType = "arraybuffer";

    this.ws.onopen = () => onOpen?.();

    this.ws.onmessage = (e) => {
      if (this.onMessage) this.onMessage(new Uint8Array(e.data));
    };

    this.ws.onclose = () => {
      if (this.onClose) this.onClose();
    };

    this.ws.onerror = (err) => {
      if (this.onError) this.onError(err);
    };
  }

  send(data) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(data);
    } else {
      console.error("🛑 WebSocket is not open");
    }
  }

  setOnMessage(callback) {
    this.onMessage = callback;
  }

  setOnClose(callback) {
    this.onClose = callback;
  }

  setOnError(callback) {
    this.onError = callback;
  }

  close() {
    if (this.ws) {
      this.ws.close();
    }
  }

  get readyState() {
    return this.ws?.readyState;
  }
}
