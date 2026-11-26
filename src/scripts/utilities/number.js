import { mountConversions } from "./fields.js";

function numericFormat(radix, pattern, digits) {
  return {
    normalize: (value) => value.replace(/\s/gu, ""),
    decode(value) {
      if (!pattern.test(value)) throw new Error(`Use only ${digits}.`);
      const prefix = { 2: "0b", 8: "0o", 10: "", 16: "0x" }[radix];
      return BigInt(prefix + value);
    },
    encode: (value) => value.toString(radix).toUpperCase(),
  };
}

export function mountNumber(panel) {
  mountConversions(panel, {
    "num-base2": numericFormat(2, /^[01]+$/u, "digits 0 and 1"),
    "num-base8": numericFormat(8, /^[0-7]+$/u, "digits 0–7"),
    "num-base10": numericFormat(10, /^\d+$/u, "digits 0–9"),
    "num-base16": numericFormat(
      16,
      /^[\da-f]+$/iu,
      "digits 0–9 and letters A–F",
    ),
    "num-ascii": {
      decode(text) {
        let number = 0n;
        for (const char of text) {
          const code = char.codePointAt(0);
          if (code > 127) throw new Error("Use ASCII characters only.");
          number = (number << 8n) | BigInt(code);
        }
        return number;
      },
      encode(number) {
        const bytes = [];
        while (number > 0n) {
          const byte = Number(number & 255n);
          if (byte > 127) return "";
          bytes.push(String.fromCharCode(byte));
          number >>= 8n;
        }
        return bytes.reverse().join("");
      },
    },
  });
}
