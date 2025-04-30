const tlRegistry = new Map();

export function register(schema) {
  const { id, name, args } = schema;
  tlRegistry.set(name, { id, args });
  tlRegistry.set(id, { name, args });
}

export function encodeTLObject(obj) {
  const schema = tlRegistry.get(obj._);
  if (!schema) throw new Error(`Unknown TL object type: ${obj._}`);
  const { id, args } = schema;
  const buffers = [Buffer.alloc(4)];
  buffers[0].writeUInt32LE(id, 0);

  for (const arg of args) {
    const val = obj[arg.name];
    buffers.push(encodeValue(val, arg.type));
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
    const paddingLength = (4 - ((len + 1) % 4)) % 4;
    const padding = Buffer.alloc(paddingLength);
    return Buffer.concat([header, strBuf, padding]);
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
    const padding = (4 - (total % 4)) % 4;
    return { value: str, readBytes: total + padding };
  }

  if (type === "true") {
    return { value: true, readBytes: 4 };
  }

  if (type.startsWith("Vector<")) {
    const subtype = type.match(/Vector<(.+)>/)[1];
    let innerOffset = offset;
    const vectorConstructor = buffer.readUInt32LE(innerOffset);
    if (vectorConstructor !== 0x1cb5c415) {
      throw new Error("Invalid vector constructor");
    }

    innerOffset += 4;
    const count = buffer.readUInt32LE(innerOffset);
    innerOffset += 4;

    const items = [];
    for (let i = 0; i < count; i++) {
      const { value, readBytes } = decodeValue(buffer, innerOffset, subtype);
      items.push(value);
      innerOffset += readBytes;
    }

    return {
      value: items,
      readBytes: innerOffset - offset,
    };
  }

  throw new Error(`Unsupported TL type: ${type}`);
}

export { tlRegistry };
