---
title: Motor City Search
challenge_type: Forensics
difficulty: Medium
author: ufosaysoof
writeup_author: "@xabito"
competition: wolvctf-2026
summary: |-
  A seized logging rig captured a controller programming session. Its recovered log fragments were concatenated out of order. Reconstruct what was flashed to the controller and find the access token inside it.
attachments:
  - title: dist.tar.gz
    url: /assets/files/wolvctf-2026/motor-city-search/dist.tar.gz
---

Before reconstructing the session, we need six protocol terms. An ECU is an
electronic control unit, and CAN is the Controller Area Network. UDS is Unified
Diagnostic Services. ISO-TP is the ISO transport protocol that splits a UDS
message across CAN frames, NRC is a Negative Response Code, and CRC32 is a
32-bit integrity checksum.

A seized logging rig recorded an ECU flashing session over CAN, but the log
fragments were concatenated out of order. The artifact unpacks to `capture.log`
(4082 lines) in candump format: `(unix_timestamp) can0 CANID#PAYLOADHEX`.

## Recon

Most of the CAN IDs are random chaff. The real story sits on the diagnostic pair
`7E0` (tester) and `7E8` (ECU), which carry an ISO 14229 (UDS) programming
session. Timestamp scanning confirms the disorder: the file jumps backwards
every ~128 lines, so a stable sort by timestamp restores chronology. Once
sorted, the session's first frames provide the roadmap. A
`ReadDataByIdentifier` response, when reassembled, reads:

```text
COMP=ZLIB;EXIT=CRC32
```

So the flashed image is zlib-compressed with a CRC32 integrity check. A
`RequestDownload` (`34`) then declared the target: address `0x00400000`, size
`0x1F4C` = 8012 bytes, with the ECU capping each `TransferData` block at 18
bytes (16 real data bytes per block).

## Flag capture

Reconstructing the firmware is a three-stage job. First, sort by timestamp and
filter to `7E0`. Second, run an ISO-TP state machine: a First Frame (`10 12`)
declares an 18-byte message, and Consecutive Frames (`21 ...`, `22 ...`) fill it
in. Standalone frames like `22 F1 C0` or `3E 00` must be excluded so they are not
mistaken for Consecutive Frames. Third, each completed 18-byte UDS message is a
`36 <blockCounter> <16 data bytes>`; the counter wraps mod 256 and one block was
retransmitted exactly, so we deduplicate consecutive duplicates.

The timestamp cutoff is not arbitrary. The first download stops after 30 blocks
when the ECU aborts the transfer, and a fresh `RequestDownload` begins one
millisecond later:

```text
(1730000000.262000) can0 7E8#037F3671AAAAAAAA
(1730000000.263000) can0 7E0#100B341044004000
```

`7F 36 71` is a negative response to `TransferData` (`0x36`) with NRC `0x71`,
`transferDataSuspended`. Selecting blocks at or after `1730000000.263` therefore
discards the aborted first pass and starts with the second pass's fresh download.

Inspecting the decompressed image revealed an embedded ZIP holding
`immo_key.bin`, which is why we carve the ZIP.

```python
import re, zlib, zipfile, io

rx = re.compile(r"\(([\d.]+)\)\s+can0\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]+)")
frames = []
for line in open('capture.log'):
    m = rx.match(line.strip())
    if m:
        frames.append((float(m.group(1)), m.group(2).upper(), m.group(3).upper()))
frames.sort(key=lambda fr: fr[0])           # defragment by timestamp

blocks, cur = [], None
for ts, cid, data in frames:
    if cid != "7E0":
        continue
    b = bytes.fromhex(data)
    if b[0] & 0xF0 == 0x10:                 # ISO-TP First Frame
        cur = bytearray(b[2:]); continue
    if 0x20 <= b[0] <= 0x2F and cur is not None:   # Consecutive Frame
        cur.extend(b[1:])
        if len(cur) >= 18:
            uds = bytes(cur[:18])
            if uds[0] == 0x36:              # TransferData payload
                blocks.append((ts, uds[1], uds[2:]))
            cur = None

p2 = [b for b in blocks if b[0] >= 1730000000.263]
img, prev = bytearray(), None
for ts, c, p in p2:
    if prev == (c, p):                      # skip exact retransmission
        continue
    prev = (c, p)
    img.extend(p)                           # 7920 bytes total

out = zlib.decompressobj().decompress(bytes(img))
i = out.find(b"PK\x03\x04")
j = out.find(b"PK\x05\x06", i)
assert i >= 0 and j >= 0
zipdata = out[i:j+22]                       # include the 22-byte ZIP end record
with zipfile.ZipFile(io.BytesIO(zipdata)) as zf:
    print(zf.read("immo_key.bin").decode())
```

The 7920-byte blob starts with the zlib magic `78 DA`. Although the declared
transfer size is 8012 bytes, the log omits the final compressed bytes;
`decompressobj` returns the available 8007-byte firmware image without requiring
the missing zlib trailer. The embedded ZIP starts at firmware offset 4856. The
carver includes the 22-byte end-of-central-directory record beginning with
`PK\x05\x06`, and `zipfile` validates the entry's stored CRC32 when reading
`immo_key.bin`, matching the `EXIT=CRC32` hint.

Running the script prints the access token:

```text
wctf{Y0U_C4N_D0_1T_9d4427e73ff7}
```
