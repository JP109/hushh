export async function sha256(buf) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

export async function computeMsgKey(authKey, message) {
  const input = new Uint8Array([...authKey.slice(88, 88 + 32), ...message]);
  const sha = await sha256(input);
  return sha.slice(8, 24);
}
