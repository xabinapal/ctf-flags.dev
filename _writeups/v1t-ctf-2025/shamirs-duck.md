---
title: Shamir's Duck
challenge_type: Crypto
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  Each duck carries a small piece of a hidden message — alone it’s useless, but together the pieces form the whole. The secret was split into 6 shares and distributed: every participant holds one little piece. No single person can reconstruct the secret, but if at least three people combine their pieces, the original message appears.
attachments:
  - title: shares.txt
    url: /assets/files/v1t-ctf-2025/shamirs-duck/shares.txt
---

## Recon

From the title, description, and the `shares.txt` file, it is clear this challenge is about **Shamir's secret sharing**. This algorithm lets you split a secret among a group so that the original can only be recovered if a minimum number of people put their pieces together. With fewer than the required number, the secret stays protected.

Shamir’s Secret Sharing works by hiding the secret as the value of a polynomial `f` at zero, or `f(0)`. The polynomial has degree at most `k-1` (for this challenge, `k=3`). Each share consists of a point `(x_i, y_i)` where `y_i = f(x_i)`. Using Lagrange interpolation, we can determine the unique polynomial over the finite field `GF(p)` that passes through any three distinct points. After reconstructing the polynomial, we simply evaluate it at `x = 0` to recover the secret.

## Exploitation

First, we need to find out which prime was used as the modulus for the field `GF(p)`. We can recover this modulus using just the information in the shares.

The threshold for reconstruction is three, so the secret is encoded by a quadratic polynomial of the form `f(x) = a*x^2 + b*x + c`. Each share gives us a point that must satisfy this equation. If we pick four shares, all four points must lie on the same curve, which means the system of equations they generate will have a determinant that is a multiple of the modulus `p`.

By calculating the determinant for several different groups of four shares and taking the greatest common divisor of those determinants, we can filter out extra factors and what remains is the `p` modulus used.

```python
from itertools import combinations

raw_shares = [
    (1, "ef73fe834623128e6f43cc923927b33350314b0d08eeb386"),  # Bob
    (2, "2c17367ded0cd22e15220a2b2a6cede16e2ed64d1898bbad"),  # Sang
    (3, "e05fd9646ff27414510dec2e46032469cd60d632606c8181"),  # Khoi
    (4, "0c4de736ced3f8412307729b8bea56cc6dc74abce06a0373"),  # Long
    (5, "afe15ff509b15eb48b0e9d72fc2285094f6233ec98914312"),  # Dung
    (6, "cb1a439f208aa76e89236cb496abaf20723191c188e23f54"),  # Steve
]

points = []
for x, h in raw_shares:
    y = int(h, 16)
    points.append((ZZ(x), ZZ(y)))

determinants = []

for combo in combinations(points, 4):
    rows = []
    for (x, y) in combo:
        rows.append([x^2, x, 1, y])

    M = matrix(ZZ, rows)
    d = M.det()

    if d != 0:
        determinants.append(abs(d))

g = determinants[0]
for d in determinants[1:]:
    g = gcd(g, d)

print(factor(g))
```

```bash
$ sage extract_gcd_factors.sage
2 * 6277101735386680763835789423207666416102355444464034513029
```

With the nontrivial prime identified, we can write a script that uses a group of any three shares. Using these, we apply Lagrange interpolation to reconstruct the polynomial and recover the flag by evaluating the polynomial at zero.

```python
from Crypto.Util.number import long_to_bytes

from itertools import combinations
from string import printable

raw_shares = [
    (1, "ef73fe834623128e6f43cc923927b33350314b0d08eeb386"),  # Bob
    (2, "2c17367ded0cd22e15220a2b2a6cede16e2ed64d1898bbad"),  # Sang
    (3, "e05fd9646ff27414510dec2e46032469cd60d632606c8181"),  # Khoi
    (4, "0c4de736ced3f8412307729b8bea56cc6dc74abce06a0373"),  # Long
    (5, "afe15ff509b15eb48b0e9d72fc2285094f6233ec98914312"),  # Dung
    (6, "cb1a439f208aa76e89236cb496abaf20723191c188e23f54"),  # Steve
]

p = 6277101735386680763835789423207666416102355444464034513029
F = GF(p)

shares = []
for x, h in raw_shares:
    y = int(h, 16)
    shares.append((F(x), F(y)))

combo = next(combinations(shares, 3))

R.<x> = F[]  # Polynomial ring over F
f = R.lagrange_polynomial(combo)

secret_field = f(0)
secret_int = ZZ(secret_field)

data = long_to_bytes(secret_int)
decoded = data.decode()
print("Flag:", decoded)
```

## Flag capture

Now we simply run the script to get our flag:

```bash
$ sage extract_flag.sage
Flag: *v1t{555_s3cr3t_sh4r1ng}
```