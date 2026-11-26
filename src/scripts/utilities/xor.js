import {
  errorMessage,
  fieldError,
  fieldMessage,
  utilityField,
} from "./fields.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function fromHex(value) {
  const hex = value.replace(/\s/gu, "");
  if (!/^(?:[\da-f]{2})*$/iu.test(hex))
    throw new Error("Enter complete hexadecimal bytes, such as 41 ff.");
  return Uint8Array.from(hex.match(/../gu) ?? [], (byte) =>
    Number.parseInt(byte, 16),
  );
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    " ",
  );
}

function toText(bytes) {
  try {
    return decoder.decode(bytes);
  } catch {
    return "";
  }
}

export function mountXor(panel) {
  const groups = ["input", "key"].map((name) => ({
    text: utilityField(panel, `xor-${name}-ascii`),
    hex: utilityField(panel, `xor-${name}-hex`),
  }));
  const resultText = utilityField(panel, "xor-output-ascii");
  const resultHex = utilityField(panel, "xor-output-hex");

  function update() {
    resultText.value = resultHex.value = "";
    fieldMessage(resultText);
    // Hex fields are the source of truth for both byte sequences.
    if (groups.some(({ hex }) => hex.hasAttribute("aria-invalid"))) return;
    const [input, key] = groups.map(({ hex }) => fromHex(hex.value));
    if (!input.length || !key.length) return;
    const bytes = input.map((byte, index) => byte ^ key[index % key.length]);
    resultHex.value = toHex(bytes);
    resultText.value = toText(bytes);
    if (!resultText.value)
      fieldMessage(resultText, "Binary result. Copy the hexadecimal output.");
  }

  for (const { text, hex } of groups) {
    text.addEventListener("input", () => {
      hex.value = toHex(encoder.encode(text.value));
      fieldError(hex);
      update();
    });
    hex.addEventListener("input", () => {
      fieldError(hex);
      try {
        text.value = toText(fromHex(hex.value));
      } catch (error) {
        text.value = "";
        fieldError(hex, errorMessage(error));
      }
      update();
    });
  }
}
