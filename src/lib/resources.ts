const resourceDescriptions: Record<string, string> = {
  crypto:
    "A toolkit for CTF cryptography challenges. Compare classical ciphers, inspect unfamiliar hashes, and work with RSA and other number puzzles.",
  forensics:
    "A collection of tools for CTF digital forensics. Unpack challenge files, examine disk and memory images, and follow clues through packet captures.",
  misc: "A collection of general-purpose tools for CTF challenges. Find network scanners, wordlists, data converters, and utilities for sharing files.",
  mobile:
    "A toolkit for Android CTF challenges. Unpack APKs, read decompiled code, and see what an app does at runtime using an emulator or debugger.",
  osint:
    "A collection of open-source intelligence tools for CTF challenges. Follow clues across usernames, domains, public records, and indexed services.",
  pwn: "A toolkit for binary challenges in CTF competitions. Use debuggers, fuzzers, and binary analysis tools to understand how challenge programs behave.",
  rev: "A collection of tools for reverse engineering CTF binaries. Compare disassembly and decompiled code, then use a debugger to see what happens at runtime.",
  stego:
    "A toolkit for CTF steganography challenges. Look for hidden data in images and audio, inspect metadata, and see what a spectrogram can reveal.",
  web: "A collection of tools for CTF web security challenges. Inspect requests and responses, examine web tokens, and explore how challenge applications behave.",
};

export function resourcePath(category?: string) {
  return category ? `/resources/${category}/` : "/resources/";
}

export function resourceMetadata(category?: string) {
  const description =
    "A solo enthusiast’s collection of tools for CTF challenges. Browse the toolkit by category, from cryptography and forensics to web and mobile security.";
  return {
    title: category ? `${category.toUpperCase()} resources` : "Resources",
    description: (category && resourceDescriptions[category]) || description,
  };
}
