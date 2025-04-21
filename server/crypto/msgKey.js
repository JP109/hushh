import { createHash } from "crypto";

export function computeMsgKey(authKey, plaintext) {
  const data = Buffer.concat([authKey.subarray(88, 88 + 32), plaintext]);
  const sha = createHash("sha256").update(data).digest();
  return sha.subarray(8, 24); // 16-byte msg_key
}
