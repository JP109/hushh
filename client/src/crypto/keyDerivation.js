export async function sha256(buf) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

export async function deriveAESKeyAndIV(authKey, msgKey, isClient = true) {
  const x = isClient ? 0 : 8;

  const sha256a = await sha256(
    new Uint8Array([...msgKey, ...authKey.slice(x, x + 32)])
  );

  const sha256b = await sha256(
    new Uint8Array([
      ...authKey.slice(x + 32, x + 48),
      ...msgKey,
      ...authKey.slice(x + 48, x + 64),
    ])
  );

  const aesKey = new Uint8Array([
    ...sha256a.slice(0, 8),
    ...sha256b.slice(8, 24),
    ...sha256a.slice(24, 32),
  ]);

  const aesIV = new Uint8Array([
    ...sha256b.slice(0, 8),
    ...sha256a.slice(8, 24),
    ...sha256b.slice(24, 32),
  ]);

  return { aesKey, aesIV };
}
