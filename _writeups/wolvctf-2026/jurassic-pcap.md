---
title: Jurassic PCAP
challenge_type: Forensics
difficulty: Medium
author: TheRealKwick
writeup_author: "@xabito"
competition: wolvctf-2026
summary: |-
  I (Codex) made a new site about dinosaurs. It's fossil-tastic! Let me send it on over.
attachments:
  - title: dist.tar.gz
    url: /assets/files/wolvctf-2026/jurassic-pcap/dist.tar.gz
---

The handout unpacks to a 1.2 MB packet capture, `jurassic.pcap`, recording an
HTTP session in which a browser downloads a small museum-style dinosaur site:
`index.html`, `style.css`, and seven JPEGs (`hero-dinosaur.jpg`, `allosaurus.jpg`,
`stegosaurus.jpg`, `brachiosaurus.jpg`, `diplodocus.jpg`, `archaeopteryx.jpg`,
`compsognathus.jpg`).

## Recon

The traffic itself is clean. We rebuilt every TCP stream and confirmed each
HTTP body matched its `Content-Length` byte-for-byte, then grepped the raw bytes
for `wctf`, base64, and hex encodings, but found nothing. Basic carving and stego
checks found nothing after the JPEG EOI (End of Image marker), in COM/APPn
segments (JPEG comment/application segment types), or through DCT (Discrete
Cosine Transform) or LSB (least significant bit) decoding, so we exported every
HTTP object to test the images individually:

```bash
tshark -r jurassic.pcap --export-objects http,http_objects
ls http_objects
# allosaurus.jpg  archaeopteryx.jpg  brachiosaurus.jpg  compsognathus.jpg
# diplodocus.jpg  hero-dinosaur.jpg  stegosaurus.jpg ...
```

We did not know which image carried the payload. Our standard first pass was an
empty-passphrase `steghide` extraction over all seven JPEGs:

```bash
mkdir -p empty_pass
for f in http_objects/*.jpg; do
  steghide extract -sf "$f" -p "" -xf "empty_pass/${f##*/}.out" 2>/dev/null
done
```

Six images refused the empty passphrase, while `stegosaurus.jpg` yielded a
31-byte file containing:

```text
Close, the flag is flown high.
```

We read "flown high" as a pointer to the flying dinosaur in the set,
`archaeopteryx.jpg`. That gave us a specific target for a passphrase crack, so
we moved from the broad empty-passphrase sweep to `stegseek` on that one image.

## Flag capture

We ran `stegseek` with the `rockyou.txt` wordlist against just `archaeopteryx.jpg`:

```bash
$ stegseek http_objects/archaeopteryx.jpg rockyou.txt archaeopteryx.txt
[i] Original filename: "flag.txt".
[i] Extracting to "archaeopteryx.txt".
```

StegSeek recovered a valid passphrase and reported the embedded payload's original name:

```bash
cat archaeopteryx.txt
wctf{th1s_1s_the_fl@g_trust_m3_SJGYBG}
```
