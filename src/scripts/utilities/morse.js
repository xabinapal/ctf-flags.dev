import { mountConversions } from "./fields.js";

const morseCode = {
  A: ".-",
  B: "-...",
  C: "-.-.",
  D: "-..",
  E: ".",
  F: "..-.",
  G: "--.",
  H: "....",
  I: "..",
  J: ".---",
  K: "-.-",
  L: ".-..",
  M: "--",
  N: "-.",
  O: "---",
  P: ".--.",
  Q: "--.-",
  R: ".-.",
  S: "...",
  T: "-",
  U: "..-",
  V: "...-",
  W: ".--",
  X: "-..-",
  Y: "-.--",
  Z: "--..",
  0: "-----",
  1: ".----",
  2: "..---",
  3: "...--",
  4: "....-",
  5: ".....",
  6: "-....",
  7: "--...",
  8: "---..",
  9: "----.",
  ".": ".-.-.-",
  ",": "--..--",
  "?": "..--..",
  "'": ".----.",
  "!": "-.-.--",
  "/": "-..-.",
  "(": "-.--.",
  ")": "-.--.-",
  "&": ".-...",
  ":": "---...",
  ";": "-.-.-.",
  "=": "-...-",
  "+": ".-.-.",
  "-": "-....-",
  _: "..--.-",
  '"': ".-..-.",
  $: "...-..-",
  "@": ".--.-.",
};

const reverse = new Map(
  Object.entries(morseCode).map(([letter, signal]) => [signal, letter]),
);

function encode(value) {
  return [...value.toUpperCase()]
    .map((char) => {
      if (/\s/u.test(char)) return "/";
      const signal = morseCode[char];
      if (!signal) throw new Error(`No Morse code for “${char}”.`);
      return signal;
    })
    .join(" ");
}

function decode(value) {
  return value
    .split(/\s+/u)
    .map((signal) => {
      if (signal === "/") return " ";
      const char = reverse.get(signal);
      if (!char) throw new Error("Unknown Morse sequence.");
      return char;
    })
    .join("");
}

export function mountMorse(panel) {
  mountConversions(panel, {
    "morse-plaintext": {
      encode: (value) => value,
      decode: (value) => {
        encode(value);
        return value;
      },
    },
    "morse-encoded": { normalize: (value) => value.trim(), encode, decode },
  });
}
