export const g = 3n;

export const MODP_P = BigInt(
  "0x" +
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
);

export function modPow(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = base % modulus;
  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exponent = exponent >> 1n; // divide by 2
    base = (base * base) % modulus;
  }
  return result;
}

export function randomBigInt(nBytes = 256) {
  const bytes = crypto.getRandomValues(new Uint8Array(nBytes));
  return BigInt(
    "0x" + [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")
  );
}

export function bigintToBytes(b, length = 256) {
  let hex = b.toString(16).padStart(length * 2, "0");
  return Uint8Array.from(hex.match(/.{2}/g).map((byte) => parseInt(byte, 16)));
}

export function bytesToBigInt(bytes) {
  return BigInt(
    "0x" + [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")
  );
}
