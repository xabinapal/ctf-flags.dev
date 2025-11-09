---
title: Linearity
challenge_type: Crypto
author: "@BIGMONKE"
writeup_author: "@xabito"
competition: infobahn-ctf-2025
summary: |-
  A gentle introduction to linear cryptanalysis 🙂
attachments:
  - title: chall.py
    url: /assets/files/infobahn-ctf-2025/linearity/chall.py
---

## Recon

In this challenge, we are given a Python encryption script that uses a matrix-based XOR encryption scheme. Alongside the script, we receive the encrypted flag and its SHA-256 hash for verification. The encryption process is based on three main components:

```python
V = [randint(0, 100) for i in range(5)]
M = [[V[i] * randint(0, 100) for i in range(5)] for i in range(5)]
C = [M[i // 5 % 5][i % 5] ^ ord(FLAG[i]) for i in range(len(FLAG))]
```

The script generates a 5-element vector `V`, constructs a 5x5 matrix `M` where each element is `V[col] * random_int(0, 100)`, and then encrypts each character of the flag by XORing it with a matrix element. The encryption uses a cyclic pattern through the matrix based on the character's position.

The key vulnerability lies in the cipher's linearity and the availability of known plaintext. Since we know the flag begins with `infobahn{` and ends with `}`, we have 10 known characters. The XOR self-inverse property means that if `C[i] = M[row][col] ^ FLAG[i]`, then `M[row][col] = C[i] ^ FLAG[i]`.

## Exploitation

With the known prefix `infobahn{` and suffix `}`, we could recover 10 matrix values. Because the encryption pattern is cyclic, the same elements of the matrix `M` are reused at different positions within the ciphertext.

```python
from hashlib import sha256

V = [14, 38, 56, 76, 51]
C = [1357, 2854, 1102, 1723, 4416, 283, 344, 4566, 5023, 1798, 477, 3833, 1839, 5416, 4017, 1066, 161, 415, 5637, 1696, 1058, 3025, 5286, 5141, 3818, 1373, 2839, 1102, 1764, 4432, 313, 322, 4545, 5012, 1835, 477, 3825]

M = [[None for _ in range(5)] for _ in range(5)]

known_prefix = "infobahn{"
known_suffix = "}"

for i, char in enumerate(known_prefix):
    row = (i // 5) % 5
    col = i % 5
    matrix_value = C[i] ^ ord(char)
    M[row][col] = matrix_value

last_idx = len(C) - 1
row = (last_idx // 5) % 5
col = last_idx % 5
matrix_value = C[last_idx] ^ ord('}')
M[row][col] = matrix_value

for i, row in enumerate(M):
    print(f"{row}")

flag = ""
for i in range(len(C)):
    row = (i // 5) % 5
    col = i % 5
    if M[row][col] is not None:
        plaintext_char = chr(C[i] ^ M[row][col])
        flag += plaintext_char
    else:
        flag += "?"

print(f"Partial flag: {flag}")
```

By substituting the recovered matrix values, we are able to decrypt positions `0-8`, `11`, `25-30`, and `32-36`, which reveals part of the original flag:

```bash
$ python3 extract_partial_flag.py
[1316, 2888, 1064, 1748, 4386]
[378, 304, 4536, 5092, None]
[None, 3724, None, None, None]
[None, None, None, None, None]
[None, None, None, None, None]
Partial flag: infobahn{??u?????????????y_f0rCryp??}
```

```python
M[0][0] =  C[0] ^ ord('i') = 1316
M[0][1] =  C[1] ^ ord('n') = 2888
M[0][2] =  C[2] ^ ord('f') = 1064
M[0][3] =  C[3] ^ ord('o') = 1748
M[0][4] =  C[4] ^ ord('b') = 4386
M[1][0] =  C[5] ^ ord('a') =  378
M[1][1] =  C[6] ^ ord('h') =  304
M[1][2] =  C[7] ^ ord('n') = 4536
M[1][3] =  C[8] ^ ord('{') = 5092
M[2][1] = C[36] ^ ord('}') = 3724
```

With almost half matrix entries now determined, we can brute-force the remaining unknown values by trying all possibilities of the form `M[row][col] = V[col] * k` for each `k` in the range `[0, 100]` and ignoring the ones that produce non-printable ASCII plaintexts. For each resulting combination, we check if the resulting flag, after decryption, matches the expected hash value:

```python
from hashlib import sha256
from itertools import product

V = [14, 38, 56, 76, 51]
C = [1357, 2854, 1102, 1723, 4416, 283, 344, 4566, 5023, 1798, 477, 3833, 1839, 5416, 4017, 1066, 161, 415, 5637, 1696, 1058, 3025, 5286, 5141, 3818, 1373, 2839, 1102, 1764, 4432, 313, 322, 4545, 5012, 1835, 477, 3825]
H = "e256693b7b7d07e11f2f83f452f04969ea327261d56406d2d657da1066cefa17"

M = [
    [1316, 2888, 1064, 1748, 4386],
    [ 378,  304, 4536, 5092, None],
    [None, 3724, None, None, None],
    [None, None, None, None, None],
    [None, None, None, None, None],
]

def find_candidates(row, col):
    base = V[col]

    candidates = []
    positions = [i for i in range(len(C)) if (i // 5) % 5 == row and i % 5 == col]

    for k in range(101):
        matrix_value = base * k
        values = []

        valid = True
        for position in positions:
            value = C[position] ^ matrix_value
            if 32 <= value <= 126:
                values.append(chr(value))
            else:
                valid = False
                break

        if valid:
            candidates.append((matrix_value, ''.join(values)))

    return candidates

candidates = []
positions = []

for i in range(len(M)):
    for j in range(len(M[i])):
        if M[i][j] is None:
            candidates.append(find_candidates(i, j))
            positions.append((i, j))

for combination in product(*candidates):
    M_test = [row[:] for row in M]

    for i, (row, col) in enumerate(positions):
        M_test[row][col] = combination[i][0]

    flag = ''
    for i in range(len(C)):
        row = (i // 5) % 5
        col = i % 5
        flag += chr(C[i] ^ M_test[row][col])

    hash = sha256(flag.encode()).hexdigest()

    if hash == H:
        print(f"Flag: {flag}")
        break
```

## Flag capture

Executing the script yields the final flag within a few seconds:

```bash
$ python3 extract_flag.py
Flag: infobahn{You_HAVE_Aff1niTy_f0rCrypto}
```