export default class MTProtoSocket {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.onMessage = null;
  }

  connect(onOpen) {
    this.ws = new WebSocket(this.url);
    this.ws.binaryType = "arraybuffer";

    this.ws.onopen = () => onOpen?.();
    this.ws.onmessage = (e) => {
      if (this.onMessage) this.onMessage(new Uint8Array(e.data));
    };
  }

  send(data) {
    this.ws.send(data);
  }

  setOnMessage(callback) {
    this.onMessage = callback;
  }
}
