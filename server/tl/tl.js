/* server/tl.js */

const tlRegistry = new Map();

export function register(schema) {
  const { id, name, args } = schema;
  tlRegistry.set(name, { id, args });
  tlRegistry.set(id, { name, args });
}

// ─── Register constructors with to_user_id for one-to-one routing ─────
register({
  id: 0x5c4d7a1f,
  name: "message",
  args: [
    { name: "to_user_id", type: "long" },
    { name: "text", type: "string" },
  ],
});
register({
  id: 0xddf60e02,
  name: "msgs_ack",
  args: [{ name: "msg_ids", type: "Vector<long>" }],
});

function encodeValue(value, type) {
  if (type === "int") {
    const buf = Buffer.alloc(4);
    buf.writeInt32LE(value, 0);
    return buf;
  }
  if (type === "long") {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64LE(BigInt(value));
    return buf;
  }
  if (type === "string") {
    const strBuf = Buffer.from(value, "utf-8");
    const len = strBuf.length;
    const header = Buffer.from([len]);
    const padLen = (4 - ((len + 1) % 4)) % 4;
    return Buffer.concat([header, strBuf, Buffer.alloc(padLen)]);
  }
  if (type === "true") {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(0x997275b5, 0);
    return buf;
  }
  if (type.startsWith("Vector<")) {
    const subtype = type.match(/Vector<(.+)>/)[1];
    const arr = value;
    const header = Buffer.alloc(8);
    header.writeUInt32LE(0x1cb5c415, 0);
    header.writeUInt32LE(arr.length, 4);
    const items = arr.map((el) => encodeValue(el, subtype));
    return Buffer.concat([header, ...items]);
  }
  throw new Error(`Unsupported TL type: ${type}`);
}

function decodeValue(buffer, offset, type) {
  if (type === "int") {
    return { value: buffer.readInt32LE(offset), readBytes: 4 };
  }
  if (type === "long") {
    return { value: buffer.readBigUInt64LE(offset), readBytes: 8 };
  }
  if (type === "string") {
    const len = buffer[offset];
    const str = buffer.slice(offset + 1, offset + 1 + len).toString("utf-8");
    const total = len + 1;
    const pad = (4 - (total % 4)) % 4;
    return { value: str, readBytes: total + pad };
  }
  if (type === "true") {
    return { value: true, readBytes: 4 };
  }
  if (type.startsWith("Vector<")) {
    const subtype = type.match(/Vector<(.+)>/)[1];
    let pos = offset;
    const ctor = buffer.readUInt32LE(pos);
    if (ctor !== 0x1cb5c415) throw new Error("Invalid vector constructor");
    pos += 4;
    const count = buffer.readUInt32LE(pos);
    pos += 4;
    const items = [];
    for (let i = 0; i < count; i++) {
      const { value, readBytes } = decodeValue(buffer, pos, subtype);
      items.push(value);
      pos += readBytes;
    }
    return { value: items, readBytes: pos - offset };
  }
  throw new Error(`Unsupported TL type: ${type}`);
}

export function encodeTLObject(obj) {
  const schema = tlRegistry.get(obj._);
  if (!schema) throw new Error(`Unknown TL object type: ${obj._}`);
  const { id, args } = schema;
  const buffers = [Buffer.alloc(4)];
  buffers[0].writeUInt32LE(id, 0);
  for (const arg of args) {
    buffers.push(encodeValue(obj[arg.name], arg.type));
  }
  return Buffer.concat(buffers);
}

export function decodeTLObject(buffer) {
  const constructorId = buffer.readUInt32LE(0);
  const schema = tlRegistry.get(constructorId);
  if (!schema) throw new Error(`Unknown constructor ID: ${constructorId}`);
  const { name, args } = schema;
  const obj = { _: name };
  let offset = 4;
  for (const arg of args) {
    const { value, readBytes } = decodeValue(buffer, offset, arg.type);
    obj[arg.name] = value;
    offset += readBytes;
  }
  return obj;
}

export { tlRegistry };
