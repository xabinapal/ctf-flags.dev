export const utilityDetails = {
  number: {
    label: "Number",
    description:
      "Convert between binary, octal, decimal, hexadecimal, and ASCII.",
  },
  base: {
    label: "Base",
    description:
      "Encode and decode text in Base32, Base45, Base58, Base62, Base64, Base85, and Base92.",
  },
  url: {
    label: "URL",
    description:
      "Percent-encode text for URLs and decode percent-encoded strings.",
  },
  rot: {
    label: "ROT",
    description: "Rotate text with a custom shift, ROT47, or ROT8000.",
  },
  xor: {
    label: "XOR",
    description: "XOR UTF-8 text or hexadecimal bytes with a repeating key.",
  },
  morse: {
    label: "Morse",
    description: "Translate between plaintext and Morse code.",
  },
  timestamp: {
    label: "Timestamp",
    description:
      "Convert between Unix timestamps, Windows FILETIME, and ISO 8601 dates.",
  },
  jwt: {
    label: "JWT",
    description: "Decode and edit JWT fields.",
  },
};

export function utilityPath(utility?: string) {
  return utility ? `/utilities/${utility}/` : "/utilities/";
}

export function utilityMetadata(utility?: keyof typeof utilityDetails) {
  const detail = utility && utilityDetails[utility];
  return detail
    ? { title: `${detail.label} utility`, description: detail.description }
    : {
        title: "Utilities",
        description:
          "Work with encodings, numbers, timestamps, and tokens in your browser.",
      };
}
