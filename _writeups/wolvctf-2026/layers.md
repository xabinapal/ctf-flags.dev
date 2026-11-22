---
title: Layers
challenge_type: Crypto
difficulty: Beginner
author: ".nerdsmith"
writeup_author: "@xabito"
competition: wolvctf-2026
summary: |-
  NjIgNjEgNzYgNjIgNjEgNjYgMmQgNzUgNmUgNjkgNzIgMmQgNzkgNmUgNmMgNzIgNjUgNjY=

  Submit wctf{flag}.
---

## Flag capture

The title warns us that the text needs more than one decoding pass.

Base64 is a printable-text encoding, often padded with `=`. Hexadecimal represents each byte as two digits. ROT13 replaces each letter with the letter 13 alphabet positions away, so `bavbaf-unir-ynlref` becomes `onions-have-layers`.

The trailing `=` suggests Base64. Decoding once produces space-separated hexadecimal bytes:

```text
62 61 76 62 61 66 2d 75 6e 69 72 2d 79 6e 6c 72 65 66
```

Hex decoding gives `bavbaf-unir-ynlref`, which ROT13 turns into `onions-have-layers`.

The following decoder performs all three steps with Python's standard library:

```python
import base64
import codecs

ciphertext = "NjIgNjEgNzYgNjIgNjEgNjYgMmQgNzUgNmUgNjkgNzIgMmQgNzkgNmUgNmMgNzIgNjUgNjY="

hex_text = base64.b64decode(ciphertext).decode("ascii")
rotated = bytes.fromhex(hex_text).decode("ascii")
message = codecs.decode(rotated, "rot_13")

print(f"wctf{{{message}}}")
```

Running it wraps the recovered phrase in the required format and prints the flag:

```bash
$ python3 solve.py
wctf{onions-have-layers}
```
