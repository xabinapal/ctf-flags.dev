import { fieldMessage, mountConversions, utilityField } from "./fields.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const alphabet32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const alphabet45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
const alphabet92 = Array.from({ length: 94 }, (_, i) =>
  String.fromCharCode(33 + i),
)
  .filter((char) => !['"', "`", "~"].includes(char))
  .join("");

function digit(alphabet, char, format) {
  const index = alphabet.indexOf(char);
  if (index < 0) throw new Error(`Invalid ${format} character “${char}”.`);
  return index;
}

const base32 = {
  encode(bytes) {
    const bits = [...bytes]
      .map((byte) => byte.toString(2).padStart(8, "0"))
      .join("");
    const symbols = (bits.match(/.{1,5}/gu) ?? [])
      .map((group) => alphabet32[Number.parseInt(group.padEnd(5, "0"), 2)])
      .join("");
    return symbols.padEnd(Math.ceil(symbols.length / 8) * 8, "=");
  },
  decode(input) {
    const normalized = input.replace(/\s/gu, "").toUpperCase();
    const digits = normalized.replace(/=+$/u, "");
    const bits = [...digits]
      .map((char) =>
        digit(alphabet32, char, "Base32").toString(2).padStart(5, "0"),
      )
      .join("");
    const bytes = Uint8Array.from(bits.match(/.{8}/gu) ?? [], (group) =>
      Number.parseInt(group, 2),
    );
    const canonical = base32.encode(bytes);
    if (
      normalized !== canonical &&
      normalized !== canonical.replace(/=+$/u, "")
    ) {
      throw new Error("Use complete Base32 groups and valid padding.");
    }
    return bytes;
  },
};

const base45 = {
  encode(bytes) {
    let result = "";
    for (let i = 0; i < bytes.length; i += 2) {
      const paired = i + 1 < bytes.length;
      const value = paired ? bytes[i] * 256 + bytes[i + 1] : bytes[i];
      result +=
        alphabet45[value % 45] + alphabet45[Math.floor(value / 45) % 45];
      if (paired) result += alphabet45[Math.floor(value / 2025)];
    }
    return result;
  },
  decode(input) {
    if (input.length % 3 === 1)
      throw new Error("Base45 ends in a group of two or three characters.");
    const bytes = [];
    for (let i = 0; i < input.length; i += 3) {
      const group = input.slice(i, i + 3);
      const value = [...group].reduce(
        (sum, char, index) =>
          sum + digit(alphabet45, char, "Base45") * 45 ** index,
        0,
      );
      if (value >= (group.length === 3 ? 65536 : 256))
        throw new Error("Base45 group exceeds its byte range.");
      if (group.length === 3) bytes.push(value >> 8);
      bytes.push(value & 255);
    }
    return Uint8Array.from(bytes);
  },
};

function byteRadix(alphabet, format) {
  const radix = BigInt(alphabet.length);
  return {
    encode(bytes) {
      let value = 0n;
      let zeros = 0;
      while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
      for (const byte of bytes) value = (value << 8n) | BigInt(byte);
      const digits = [];
      while (value > 0n) {
        digits.push(alphabet[Number(value % radix)]);
        value /= radix;
      }
      return alphabet[0].repeat(zeros) + digits.reverse().join("");
    },
    decode(input) {
      let value = 0n;
      let zeros = 0;
      while (input[zeros] === alphabet[0]) zeros++;
      for (const char of input)
        value = value * radix + BigInt(digit(alphabet, char, format));
      const bytes = [];
      while (value > 0n) {
        bytes.push(Number(value & 255n));
        value >>= 8n;
      }
      return Uint8Array.from([...Array(zeros).fill(0), ...bytes.reverse()]);
    },
  };
}

const base85 = {
  encode(bytes) {
    let result = "";
    for (let i = 0; i < bytes.length; i += 4) {
      const block = bytes.subarray(i, i + 4);
      let value = 0;
      for (let j = 0; j < 4; j++) value = value * 256 + (block[j] ?? 0);
      if (value === 0 && block.length === 4) {
        result += "z";
        continue;
      }
      const digits = [];
      for (let j = 0; j < 5; j++) {
        digits.push(String.fromCharCode(33 + (value % 85)));
        value = Math.floor(value / 85);
      }
      result += digits
        .reverse()
        .slice(0, block.length + 1)
        .join("");
    }
    return result;
  },
  decode(input) {
    const compact = input
      .replace(/\s/gu, "")
      .replace(/^<~/u, "")
      .replace(/~>$/u, "");
    const bytes = [];
    let group = "";
    const append = () => {
      if (group.length === 1)
        throw new Error(
          "An ASCII85 final group needs at least two characters.",
        );
      let value = 0;
      for (const char of group.padEnd(5, "u"))
        value = value * 85 + char.charCodeAt(0) - 33;
      if (value > 0xffffffff)
        throw new Error("ASCII85 group exceeds four bytes.");
      for (let i = 0; i < group.length - 1; i++)
        bytes.push((value >>> (24 - 8 * i)) & 255);
      group = "";
    };
    for (const char of compact) {
      if (char === "z" && group === "") bytes.push(0, 0, 0, 0);
      else {
        if (char < "!" || char > "u")
          throw new Error("Invalid ASCII85 character or misplaced z.");
        group += char;
        if (group.length === 5) append();
      }
    }
    if (group) append();
    return Uint8Array.from(bytes);
  },
};

const base92 = {
  encode(bytes) {
    if (!bytes.length) return "~";
    const bits = [...bytes]
      .map((byte) => byte.toString(2).padStart(8, "0"))
      .join("");
    return (bits.match(/.{1,13}/gu) ?? [])
      .map((group) => {
        const value = Number.parseInt(
          group.padEnd(group.length <= 6 ? 6 : 13, "0"),
          2,
        );
        return group.length <= 6
          ? alphabet92[value]
          : alphabet92[Math.floor(value / 91)] + alphabet92[value % 91];
      })
      .join("");
  },
  decode(input) {
    if (input === "~") return new Uint8Array();
    const bits = (input.match(/.{1,2}/gu) ?? [])
      .map((group) => {
        const length = group.length === 1 ? 6 : 13;
        const value = [...group].reduce(
          (sum, char) => sum * 91 + digit(alphabet92, char, "Base92"),
          0,
        );
        if (value >= 2 ** length)
          throw new Error("Base92 group exceeds its bit range.");
        return value.toString(2).padStart(length, "0");
      })
      .join("");
    const bytes = Uint8Array.from(bits.match(/.{8}/gu) ?? [], (group) =>
      Number.parseInt(group, 2),
    );
    if (base92.encode(bytes) !== input)
      throw new Error("Use complete Base92 groups and valid padding bits.");
    return bytes;
  },
};

const codecs = {
  base32,
  base45,
  base58: byteRadix(
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    "Base58",
  ),
  base62: byteRadix(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "Base62",
  ),
  base64: {
    encode: (bytes) =>
      btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join("")),
    decode(value) {
      try {
        return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
      } catch {
        throw new Error("Use valid Base64 characters and padding.");
      }
    },
  },
  base85,
  base92,
};

export function mountBase(panel) {
  const plaintext = utilityField(panel, "base-plaintext");
  mountConversions(panel, {
    "base-plaintext": {
      encode(bytes) {
        try {
          return decoder.decode(bytes);
        } catch {
          fieldMessage(plaintext, "Binary bytes. Copy an encoded form.");
          return "";
        }
      },
      decode: (value) => encoder.encode(value),
    },
    ...Object.fromEntries(
      Object.entries(codecs).map(([name, codec]) => [`base-${name}`, codec]),
    ),
  });
}
