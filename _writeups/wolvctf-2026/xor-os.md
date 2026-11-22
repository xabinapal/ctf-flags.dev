---
title: XOR OS
challenge_type: Crypto
difficulty: Hard
author: MetricBead
writeup_author: "@xabito"
competition: wolvctf-2026
summary: |-
  We found this disk image just lying around. Unfortunately, the unlock key wasn't included.
attachments:
  - title: dis.tar.gz
    url: /assets/files/wolvctf-2026/xor-os/dis.tar.gz
---

## Recon

The archive holds a single disk image, `chal.bin`. Its first sector is more than a bootloader: it also documents, verbatim, how the image is meant to be run:

```bash
qemu-system-x86_64 $0 -boot c -device loader,file=key.bin,addr=0x100000
```

QEMU would inject an external `key.bin` into memory at physical address `0x100000`, right before booting. That file is the "unlock key" the description says is missing, so we cannot boot the image directly.

The encrypted payload begins at offset `0x200`, just past the boot sector. The 16-bit boot code reads the payload and XORs it with `key.bin`, cycling through the key as it advances. The key is `0xC0DE` bytes long (49,374 in decimal), and `0xC0DE` is a hex pun on "CODE". That period is also visible in the image itself: the encrypted region is 101 complete 49,374-byte blocks followed by one partial block.

So this is repeating-key XOR, and the key is unknown. The weakness is in the plaintext, not the cipher: the payload decrypts to a GCC object archive, and an object archive is mostly padding, with long runs of zero bytes.

## Exploitation

Because the plaintext is full of zeros, we can recover the key one byte at a time without knowing a single byte of plaintext.

Line the 101 blocks up as the 101 rows of a `101 × 49374` table. Column `j` of that table is the same key position `j` across every block. Within column `j`, each ciphertext byte is `plaintext_byte ^ K[j]`. When the plaintext byte is `0x00` (which is common, thanks to the archive padding), the ciphertext byte is exactly `0x00 ^ K[j] = K[j]`. When the plaintext byte is nonzero, the ciphertext byte is some other scattered value.

That means the *most common* ciphertext byte in a column is the key byte. All the zeros vote identically for `K[j]`, while the votes from the rarer nonzero plaintext bytes are spread among many values, so none receives as many votes as the zero-padding candidate. A concrete example: if `K[0] = 0x37` and 60 of the 101 blocks hold a zero plaintext byte at position 0, then 60 of the 101 ciphertext bytes in column 0 read `0x37` and the column's mode is exactly `0x37`.

Recovering every column this way (a "column vote") yields the whole key with comfortable margins: 16 to 65 votes per position with a median of 42, and never a tie for first place. As a sanity check, the decrypted output contains recognizable strings such as `_IO_setbuffer`, archive member headers, and ELF magic, which is independent evidence that the recovered key is correct.

## Flag capture

Decrypt the payload with the recovered key. The first decrypted block does not hold a plain string: at offset `0xE0` it holds a banner rendered in a FIGlet-style fixed-width ASCII font, a grid of 15 rows by 77 columns built from `_`, `|`, `/`, `\`, and spaces. The following script recovers the key, decrypts, and prints that grid row by row so the banner is readable:

```python
import tarfile
import numpy as np

with tarfile.open("files/dis.tar.gz", "r:gz") as archive:
    data = archive.extractfile("chal.bin").read()

OFFSET = 0x200
PERIOD = 0xC0DE
block_count = (len(data) - OFFSET) // PERIOD
assert block_count == 101

ciphertext = np.frombuffer(data, dtype=np.uint8)[
    OFFSET:OFFSET + block_count * PERIOD
].reshape(block_count, PERIOD)

counts = np.zeros((PERIOD, 256), dtype=np.uint16)
positions = np.arange(PERIOD)
for block in ciphertext:
    np.add.at(counts, (positions, block), 1)

# Cast to signed before negating: unsigned counts would wrap instead of sorting.
order = np.argsort(-counts.astype(np.int32), axis=1)
key = order[:, 0].astype(np.uint8)
best = counts[positions, key]
second = counts[positions, order[:, 1]]

print("Vote minimum/median/maximum:", best.min(), np.median(best), best.max())
print("First-place ties:", np.sum(best == second))

first_block = ciphertext[0] ^ key
banner = first_block[0xE0:0xE0 + 15 * 77].decode("ascii")
for row in range(15):
    print(banner[row * 77:(row + 1) * 77])
```

Reading the banner (a "Some Time Pad" pun on "one-time pad", with leetspeak substitutions and careful attention to the lowercase `o` and uppercase `D`) gives the flag:

```text
wctf{Som3_Tim3_p4D}
```
