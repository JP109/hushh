import { randomBytes } from "crypto";

export const g = 3n;

export const MODP_P = BigInt(
  "0x" +
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
);

export function modPow(base, exp, mod) {
  return base ** exp % mod;
}

export function randomBigInt(nBytes = 256) {
  return BigInt("0x" + randomBytes(nBytes).toString("hex"));
}

export function bigintToBytes(b, length = 256) {
  const hex = b.toString(16).padStart(length * 2, "0");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}
