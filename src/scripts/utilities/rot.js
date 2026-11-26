import { fieldError, mountConversions, utilityField } from "./fields.js";

const validRanges = [
  [33, 127],
  [161, 5760],
  [5761, 8192],
  [8203, 8232],
  [8234, 8239],
  [8240, 8287],
  [8288, 12288],
  [12289, 55296],
  [57344, 65536],
];
// Rotate by half of the eligible BMP code points, skipping the excluded ranges.
const eligibleCount = validRanges.reduce(
  (count, [start, end]) => count + end - start,
  0,
);

function rot8000(value) {
  return Array.from(value, (char) => {
    const code = char.codePointAt(0);
    let preceding = 0;
    for (const [start, end] of validRanges) {
      if (code < start) break;
      if (code < end) {
        let target =
          (preceding + code - start + eligibleCount / 2) % eligibleCount;
        for (const [rangeStart, rangeEnd] of validRanges) {
          if (target < rangeEnd - rangeStart)
            return String.fromCodePoint(rangeStart + target);
          target -= rangeEnd - rangeStart;
        }
      }
      preceding += end - start;
    }
    return char;
  }).join("");
}

function rotateAscii(value, pattern, start, range, shift) {
  return value.replace(pattern, (char) => {
    const base = typeof start === "function" ? start(char) : start;
    return String.fromCharCode(
      base + ((char.charCodeAt(0) - base + shift) % range),
    );
  });
}

export function mountRot(panel) {
  const shift = utilityField(panel, "rot-n");
  const plaintext = utilityField(panel, "rot-plaintext");
  const rotate = (value, step) =>
    rotateAscii(
      value,
      /[A-Za-z]/gu,
      (char) => (char <= "Z" ? 65 : 97),
      26,
      step,
    );
  const rot47 = (value) => rotateAscii(value, /[!-~]/gu, 33, 94, 47);
  const update = mountConversions(panel, {
    "rot-plaintext": { encode: (value) => value, decode: (value) => value },
    "rot-rotn": {
      encode: (value) =>
        shift.value && shift.validity.valid
          ? rotate(value, Number(shift.value))
          : "",
      decode: (value) => {
        if (!shift.value || !shift.validity.valid)
          throw new Error("Set a valid rotation shift first.");
        return rotate(value, 26 - Number(shift.value));
      },
    },
    "rot-rot47": { encode: rot47, decode: rot47 },
    "rot-rot8000": { encode: rot8000, decode: rot8000 },
  });

  shift.addEventListener("input", () => {
    const valid = shift.value !== "" && shift.validity.valid;
    fieldError(shift, valid ? "" : "Enter a whole-number shift from 0 to 26.");
    update(plaintext.value ? plaintext.id : undefined);
  });
}
