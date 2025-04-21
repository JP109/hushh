import { ModeOfOperation, utils } from "aes-js";

function xorBlock(a, b) {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
  return out;
}

function splitBlocks(buf) {
  const blocks = [];
  for (let i = 0; i < buf.length; i += 16) {
    blocks.push(buf.slice(i, i + 16));
  }
  return blocks;
}

function addPadding(data) {
  const minPadding = 12;
  const pad = 16 - ((data.length + minPadding) % 16);
  const padded = new Uint8Array(data.length + minPadding + pad);
  padded.set(data);
  crypto.getRandomValues(padded.subarray(data.length));
  return padded;
}

export function aesIgeEncrypt(plaintext, key, iv) {
  const padded = addPadding(plaintext);
  const aesEcb = new ModeOfOperation.ecb(key);
  const blocks = splitBlocks(padded);
  const iv1 = iv.slice(0, 16);
  const iv2 = iv.slice(16, 32);
  let xPrev = iv1;
  let yPrev = iv2;
  const out = [];

  for (const block of blocks) {
    const xored = xorBlock(block, yPrev);
    const encrypted = aesEcb.encrypt(xored);
    const y = xorBlock(encrypted, xPrev);
    out.push(...y);
    xPrev = block;
    yPrev = y;
  }

  return new Uint8Array(out);
}

export function aesIgeDecrypt(ciphertext, key, iv) {
  const aesEcb = new ModeOfOperation.ecb(key);
  const blocks = splitBlocks(ciphertext);
  const iv1 = iv.slice(0, 16);
  const iv2 = iv.slice(16, 32);
  let xPrev = iv1;
  let yPrev = iv2;
  const out = [];

  for (const block of blocks) {
    const xored = xorBlock(block, xPrev);
    const decrypted = aesEcb.decrypt(xored);
    const x = xorBlock(decrypted, yPrev);
    out.push(...x);
    xPrev = x;
    yPrev = block;
  }

  return new Uint8Array(out);
}
