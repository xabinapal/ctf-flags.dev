---
title: "On the Rail Fence"
challenge_type: Crypto
difficulty: Beginner
author: ".nerdsmith"
writeup_author: "@xabito"
competition: wolvctf-2026
summary: |-
  What's the name of my favorite song?

  H!hcsiH!hnrheiatcaedaeatetvaateqiesliohnemntealtteitrvlataltteoq'igeosal
  Hi!oihgnhlaesnbsHi!ohvcosainHi!ohcnurnhreHi!altMcia,hcaposfhWs!iovoanioc
  unrH!lMiterdtltirltlto'goaH!igthioet

  P.S. Use all lowercase for the flag, and replace spaces with dashes. Submit wctf{song}.
---

## Recon

The title points to a rail fence transposition, leaving the rail count as the only unknown.

## Flag capture

Encryption writes plaintext diagonally across a fixed number of rails, then reads each rail from left to right. Only the order changes, so the ciphertext retains every plaintext character. The repeated `Hi!` fragments look like pieces of a repeated lyric.

To decrypt, we reconstruct the zigzag pattern, count the characters assigned to each rail, and slice the ciphertext into rails of those sizes. Walking through the pattern again and taking one character from the corresponding rail restores the original order. Trying small rail counts should therefore expose coherent English.

The following script tries rail counts from two through ten:

```python
CT = "H!hcsiH!hnrheiatcaedaeatetvaateqiesliohnemntealtteitrvlataltteoq'igeosalHi!oihgnhlaesnbsHi!ohvcosainHi!ohcnurnhreHi!altMcia,hcaposfhWs!iovoaniocunrH!lMiterdtltirltlto'goaH!igthioet"


def decrypt(ciphertext, rail_count):
    cycle = list(range(rail_count)) + list(range(rail_count - 2, 0, -1))
    repeats = (len(ciphertext) + len(cycle) - 1) // len(cycle)
    pattern = (cycle * repeats)[:len(ciphertext)]

    rails = []
    offset = 0
    for rail in range(rail_count):
        size = pattern.count(rail)
        rails.append(iter(ciphertext[offset:offset + size]))
        offset += size

    return "".join(next(rails[rail]) for rail in pattern)


for count in range(2, 11):
    print(count, decrypt(CT, count))
```

Using three rails decrypts the text to lyrics beginning `Hail! to the victors valiant` and continuing through `Hail! Hail! to Michigan, the champions of the West!`. The other candidates remain scrambled. These lyrics identify **The Victors**, the University of Michigan fight song.

Following the description's formatting rules, which require lowercase and dashes instead of spaces, and adding the usual wrapper gives:

```text
wctf{the-victors}
```
