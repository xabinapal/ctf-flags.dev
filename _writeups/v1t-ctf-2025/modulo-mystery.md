---
title: Modulo Mystery
challenge_type: Crypto
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  Can you find the number?
attachments:
  - title: modulo.zip
    url: /assets/files/v1t-ctf-2025/modulo-mystery/modulo.zip
---

## Recon

We are provided with an encrypted flag and the Python script that generated it. By examining the script, we see that it chooses a random key between 1 and 100 and applies the modulo operation to each character's ASCII value using this key. This method is inherently lossy because the modulo operation does not uniquely identify the original value; multiple possible bytes can result in the same output.

```python
def encrypt(pt):
    key = random.randint(1, 100)
    results = [str(ord(ch) % key) for ch in pt]
    print("Encrypted:", " ".join(results))
    with open('flag.enc', 'w') as f:
        f.write(" ".join(results))
    return key
```

## Exploitation

Our first step is to recover the original key used for encryption. We can do this by leveraging our knowledge of the flag's known prefix, `v1t{`. For each character in this substring, we examine the relationship between its ASCII value and the corresponding encrypted output:

- `ord('v') % key = 16` → `118 % key = 16`
- `ord('1') % key = 49` → `49 % key = 49`
- `ord('t') % key = 14` → `116 % key = 14`
- `ord('{') % key = 21` → `123 % key = 21`

Using a simple Python script, we can brute-force all possible keys and identify the one that satisfies all these conditions simultaneously:

```python
encrypted = [16, 49, 14, 21, 7, 48, 49, 15, 6, 48, 44, 10, 12, 49, 20, 0, 23]
known_prefix = "v1t{"

valid_keys = set(range(1, 101))

for i, ch in enumerate(known_prefix):
    ascii_val = ord(ch)
    encrypted_val = encrypted[i]

    possible_keys = set()
    for key in valid_keys:
        if ascii_val % key == encrypted_val:
            possible_keys.add(key)

    valid_keys = valid_keys & possible_keys

print(valid_keys)
```

```bash
$ python3 brute_force_key.py
{51}
```

With `key = 51`, each encrypted value corresponds to at most two possible printable ASCII characters:

| Position | Encrypted | Possible Characters |
|----------|-----------|---------------------|
| 4        | 7         | `:` (58), `m` (109) |
| 5        | 48        | `0` (48), `c` (99)  |
| 6        | 49        | `1` (49), `d` (100) |
| 7        | 15        | `B` (66), `u` (117) |
| 8        | 6         | `9` (57), `l` (108) |
| 9        | 48        | `0` (48), `c` (99)  |
| 10       | 44        | `,` (44), `_` (95)  |
| 11       | 10        | `=` (61), `p` (112) |
| 12       | 12        | `?` (63), `r` (114) |
| 13       | 49        | `1` (49), `d` (100) |
| 14       | 20        | `G` (71), `z` (122) |
| 15       | 0         | `3` (51), `f` (102) |
| 16       | 23        | `J` (74), `}` (125) |

This results in a total of `2^17` possible character combinations. However, by restricting the allowed characters to lowercase alphanumerics, underscores, and curly brackets, we can significantly reduce the number of valid outputs.

The following Python script generates all possible flags that meet these criteria:

```python
encrypted = [16, 49, 14, 21, 7, 48, 49, 15, 6, 48, 44, 10, 12, 49, 20, 0, 23]
key = 51

possibilities = []

for i in range(2**len(encrypted)):
    possibility = ""
    for j, char in enumerate(encrypted):
        if char < 32:
            char += key
        possibility += chr(char) if i & (1 << j) else chr(char + key)

    if not possibility.startswith('v1t{') or not possibility.endswith('}'):
        continue

    if all(c.isalnum() or c in ['{', '}', '_'] for c in possibility):
        possibilities.append(possibility)

for possibility in sorted(possibilities):
    print(possibility)
```

```bash
$ python3 brute_force_flag.py
v1t{m01B90_pr1G3}
v1t{m01B90_pr1z3}
v1t{m01ul0_pr1G3}
v1t{m01ul0_pr1Gf}
v1t{m01ul0_pr1z3}
v1t{m01ulc_prdz3}
v1t{m01ulc_prdzf}
v1t{m0dB9c_pr1z3}
v1t{m0dBl0_prdG3}
v1t{m0du90_pr1z3}
v1t{m0dul0_prdzf}
...
```

## Flag capture

These combinations appear to form the words `modulo` and `prize` written in leetspeak. Therefore, the most likely flags are `v1t{m0dul0_pr1z3}` and `v1t{m0du10_pr1z3}`. Since both options are present in the generated list, we should try each of them to determine the correct flag.

```
Flag: v1t{m0dul0_pr1z3}
```