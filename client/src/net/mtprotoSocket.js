export default class MTProtoSocket {
  constructor(url) {
    this.url = url;
    this.ws = null;
  }

  connect() {
    this.ws = new WebSocket(this.url);
    this.ws.binaryType = "arraybuffer";

    this.ws.onopen = () => console.log("🔌 Connected to server");
    this.ws.onmessage = (e) =>
      this.onMessage && this.onMessage(new Uint8Array(e.data));
  }

  send(data) {
    this.ws.send(data);
  }

  onMessage(callback) {
    this.onMessage = callback;
  }
}
