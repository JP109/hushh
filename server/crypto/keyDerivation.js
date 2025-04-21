import { createHash } from "crypto";

function sha1(data) {
  return createHash("sha1").update(data).digest();
}

function sha256(data) {
  return createHash("sha256").update(data).digest();
}

export function deriveAESKeyAndIV(authKey, msgKey, isClient = false) {
  const x = isClient ? 0 : 8;

  const sha256a = sha256(Buffer.concat([msgKey, authKey.subarray(x, x + 32)]));

  const sha256b = sha256(
    Buffer.concat([
      authKey.subarray(x + 32, x + 48),
      msgKey,
      authKey.subarray(x + 48, x + 64),
    ])
  );

  const aesKey = Buffer.concat([
    sha256a.subarray(0, 8),
    sha256b.subarray(8, 24),
    sha256a.subarray(24, 32),
  ]);

  const aesIV = Buffer.concat([
    sha256b.subarray(0, 8),
    sha256a.subarray(8, 24),
    sha256b.subarray(24, 32),
  ]);

  return { aesKey, aesIV };
}
