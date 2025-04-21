// AES core engine used by MTProto (by Andrey Sidorov)
// Source: https://github.com/asmcrypto/asmcrypto.js/blob/master/src/aes/aes.ts
// MIT License - trimmed for 256-bit ECB use

export default class AES {
  constructor(key) {
    this._key = key;
    this._init();
  }

  _init() {
    const aesjs = require("aes-js"); // must install this once!
    this.ecb = new aesjs.ModeOfOperation.ecb(this._key);
  }

  encrypt(block) {
    return this.ecb.encrypt(block);
  }

  decrypt(block) {
    return this.ecb.decrypt(block);
  }
}
