import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

function xorBlocks(a, b) {
  const out = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    out[i] = a[i] ^ b[i];
  }
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
  return Buffer.concat([data, randomBytes(minPadding + pad)]);
}

export function aesIgeEncrypt(plaintext, key, iv) {
  const padded = addPadding(Buffer.from(plaintext));
  const cipher = createCipheriv("aes-256-ecb", key, null);
  cipher.setAutoPadding(false);

  const iv1 = iv.slice(0, 16);
  const iv2 = iv.slice(16, 32);

  let xPrev = iv1;
  let yPrev = iv2;

  const blocks = splitBlocks(padded);
  const encrypted = [];

  for (const block of blocks) {
    const xored = xorBlocks(block, yPrev);
    const encryptedBlock = cipher.update(xored);
    const output = xorBlocks(encryptedBlock, xPrev);
    encrypted.push(output);
    xPrev = block;
    yPrev = output;
  }

  return Buffer.concat(encrypted);
}

export function aesIgeDecrypt(ciphertext, key, iv) {
  const decipher = createDecipheriv("aes-256-ecb", key, null);
  decipher.setAutoPadding(false);

  const iv1 = iv.slice(0, 16);
  const iv2 = iv.slice(16, 32);

  let xPrev = iv1;
  let yPrev = iv2;

  const blocks = splitBlocks(ciphertext);
  const decrypted = [];

  for (const block of blocks) {
    const xored = xorBlocks(block, xPrev);
    const decryptedBlock = decipher.update(xored);
    const output = xorBlocks(decryptedBlock, yPrev);
    decrypted.push(output);
    xPrev = output;
    yPrev = block;
  }

  return Buffer.concat(decrypted); // padding left in place
}
