---
title: A Very Meta CTF
challenge_type: Forensics
difficulty: easy
author: camelot007
writeup_author: "xabito"
competition: wolvctf-2026
summary: |-
  Ten pictures were found on a pirate's computer. Can you recover the message hidden in them?
attachments:
  - title: dist.tar.gz
    url: /assets/files/wolvctf-2026/a-very-meta-ctf/dist.tar.gz
---

## Recon

The challenge hands us ten 400×400 PNGs, named `one.png` through `ten.png`,
each depicting a large number from 1 through 10 (`four.png` shows the two-digit
number 10).

The title's emphasis on "**Meta**" directed us to each file's
*metadata* rather than its pixels. A sweep with `exiftool` confirmed that every
PNG carries an `eXIf` chunk whose EXIF `UserComment` holds a short hex string,
while every other EXIF field is identical boilerplate across all ten files:

```bash
for f in pictures/*.png; do
  printf '%s ' "$f"; exiftool -s3 -UserComment "$f" | xxd -r -p; echo
done
```

Hex-decoding each fragment yields printable ASCII pieces, several containing
recognizable flag delimiters: `wc` (the prefix start), `{t` (the opening brace),
and one fragment ending in `}`. The remaining problem was their order.

Neither the filenames nor the depicted numbers provide the fragment order.
Filename order (`one.png` → `ten.png`) produces
`s_g_IE0j32e}l4{ttf_41swch1_f`, which is garbage. Sorting by the depicted number
also fails: it puts `_f` second and the `}`-terminated fragment fourth, closing
the message before most of the pieces. The numbers are visual decoys, so the
fragments must instead be ordered by their contents and the known flag syntax.

## Flag capture

The opening is constrained: `wc` is the only fragment containing `w`, and adding
`tf` followed by `{t` completes the standard five-character opening. The next
pieces `h1`, `s_`, and `1s` spell `th1s_1s`. The remaining fragments have one
coherent assembly, ending with the only fragment containing `}`:

1. `eight.png`: `wc`
2. `five.png`: `tf`
3. `four.png`: `{t`
4. `nine.png`: `h1`
5. `one.png`: `s_`
6. `seven.png`: `1s`
7. `six.png`: `_4`
8. `ten.png`: `_f`
9. `three.png`: `l4`
10. `two.png`: `g_IE0j32e}`

```text
wctf{th1s_1s_4_fl4g_IE0j32e}
```
