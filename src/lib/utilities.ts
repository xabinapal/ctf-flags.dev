export const utilityDetails = {
  number: {
    label: "Number",
    description:
      "A browser-based number converter for CTF challenges. Edit binary, octal, decimal, hexadecimal, or ASCII text to see the corresponding values.",
  },
  base: {
    label: "Base",
    description:
      "A browser-based toolkit for common CTF encodings. Convert text and bytes between Base32, Base45, Base58, Base62, Base64, ASCII85, and Base92.",
  },
  url: {
    label: "URL",
    description:
      "A browser-based URL encoding tool for CTF challenges. Turn text into percent-encoded characters or decode URL escapes back into readable text.",
  },
  rot: {
    label: "ROT",
    description:
      "A browser-based rotation cipher tool for CTF challenges. Try a custom alphabet shift, ROT47 for printable ASCII, or ROT8000 for Unicode text.",
  },
  xor: {
    label: "XOR",
    description:
      "A browser-based XOR calculator for CTF challenges. Apply a repeating key to UTF-8 text or hexadecimal bytes, then read the result as text or hex.",
  },
  morse: {
    label: "Morse",
    description:
      "A browser-based Morse code translator for CTF challenges. Convert text to dots and dashes, or decode a string of Morse signals back into letters.",
  },
  timestamp: {
    label: "Timestamp",
    description:
      "A browser-based timestamp converter for CTF challenges. Switch between Unix seconds, milliseconds, nanoseconds, Windows FILETIME, and ISO 8601.",
  },
  jwt: {
    label: "JWT",
    description:
      "A browser-based JWT editor for CTF challenges. Read the header and payload as JSON, then edit either field or the signature to rebuild the token.",
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
          "A browser-based workbench for solving CTF challenges. Make quick conversions and inspect unfamiliar data, with all inputs processed locally.",
      };
}
