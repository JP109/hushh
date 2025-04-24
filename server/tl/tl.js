// tl.js
const tlRegistry = new Map();

/**
 * Registers a TL constructor with a unique ID and argument spec
 */
export function register(schema) {
  const { id, name, args } = schema;
  tlRegistry.set(name, { id, args });
}

/**
 * Encodes a TL object to a Uint8Array
 */
export function encodeTLObject(obj) {
  const schema = tlRegistry.get(obj._);
  if (!schema) throw new Error(`Unknown TL object type: ${obj._}`);

  const { id, args } = schema;
  const buffers = [];

  // Constructor ID (little-endian)
  const constructor = Buffer.alloc(4);
  constructor.writeUInt32LE(id, 0);
  buffers.push(constructor);

  for (const arg of args) {
    const val = obj[arg.name];
    buffers.push(encodeValue(val, arg.type));
  }

  return Buffer.concat(buffers);
}

/**
 * Encodes a single TL value based on type
 */
function encodeValue(value, type) {
  if (type === "int") {
    const buf = Buffer.alloc(4);
    buf.writeInt32LE(value, 0);
    return buf;
  }

  if (type === "long") {
    const buf = Buffer.alloc(8);
    BigInt.asUintN(64, BigInt(value));
    buf.writeBigUInt64LE(BigInt(value));
    return buf;
  }

  if (type === "string") {
    const strBuf = Buffer.from(value, "utf-8");
    const len = strBuf.length;
    const header = Buffer.from([len]);
    const padding = Buffer.alloc(-(len + 1) % 4); // align to 4
    return Buffer.concat([header, strBuf, padding]);
  }

  if (type === "true") {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(0x997275b5, 0); // Magic constant for true
    return buf;
  }

  if (type.startsWith("Vector<")) {
    const subtype = type.match(/Vector<(.+)>/)[1];
    const arr = value;
    const header = Buffer.alloc(4);
    header.writeUInt32LE(0x1cb5c415, 0); // vector constructor
    const count = Buffer.alloc(4);
    count.writeUInt32LE(arr.length, 0);
    const items = arr.map((el) => encodeValue(el, subtype));
    return Buffer.concat([header, count, ...items]);
  }

  throw new Error(`Unsupported TL type: ${type}`);
}
