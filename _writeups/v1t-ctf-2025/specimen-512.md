---
title: Specimen 512
challenge_type: Misc
author: "@Shah Ji"
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  An unmarked data file was recovered from an abandoned research server labeled only as Specimen 512. No accompanying documentation, no metadata, and no obvious contents — just a massive file filled with strange sequences. Some say it hides a secret
attachments:
  - title: Specimen_512.zip
    url: /assets/files/v1t-ctf-2025/specimen-512/Specimen_512.zip
---

## Recon

The challenge provides a `FASTA` file, which is a common format in bioinformatics for storing nucleotide or protein sequences. Looking inside the file, we notice several hints. The most important one says `encoding=base64->triplet-codon (lexicographic AAA..TTT => b64 idx 0..63)`.

Within the file, there are multiple sequences, each starting with a `>` character. For decoding, each nucleotide is used to form a triplet, resulting in 64 possible triplets overall. These triplets represent all values in the base64 alphabet. To decode the message, each triplet is mapped to a base64 value according to lexicographic order, where `AAA = 0` (`A`), `AAC = 1` (`B`), and so on.

## Exploitation

The script below reads the `FASTA` file, decodes each sequence on its own using the base64 method described by the encoding hint, and saves the decoded content to a file.

```python
import base64
import itertools

nucleotides = 'ACGT'
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

triplets = {
    "".join(triplet): alphabet[i]
    for i, triplet in enumerate(itertools.product(nucleotides, repeat=3))
}

sequences = []
with open('Specimen_512.fasta', 'r') as f:
    for line in f.readlines():
        if line.startswith(';'):
            continue
        elif line.startswith('>'):
            sequences.append("")
        else:
            line = line.strip()
            sequences[-1] += line

for idx, sequence in enumerate(sequences):
    encoded = ""
    for i in range(0, len(sequence), 3):
        triplet = sequence[i:i+3]
        if len(triplet) == 3:
            encoded += triplets[triplet]

    decoded = base64.b64decode(encoded + "==")
    with open(f'sequence_{idx}.bin', 'wb') as f:
        print(f'Written file {f.name}')
        f.write(decoded)
```

Once all the sequences have been converted, we should inspect their contents to see if anything interesting is inside.

```bash
$ ls *.bin | xargs -L1 binwalk -e
Analyzed 1 file for 85 file signatures (187 magic patterns) in 2.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 4.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds

extractions/sequence_2.bin
---------------------------------------------------------------------------------
DECIMAL      HEXADECIMAL      DESCRIPTION
---------------------------------------------------------------------------------
10000        0x2710           ZIP archive, file count: 2, total size: 298 bytes
---------------------------------------------------------------------------------
[+] Extraction of zip data at offset 0x2710 completed successfully
---------------------------------------------------------------------------------

Analyzed 1 file for 85 file signatures (187 magic patterns) in 13.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
Analyzed 1 file for 85 file signatures (187 magic patterns) in 1.0 milliseconds
```

## Flag capture

Next, we can look at the contents of the extracted ZIP to see what files were recovered:

```bash
$ tree extractions/sequence_2.bin.extracted
extractions/sequence_2.bin.extracted
└── 2710
    ├── flag.txt
    └── readme.txt

2 directories, 2 files

$ cat extractions/sequence_2.bin.extracted/2710/readme.txt
This is a DNA Archive payload. Life finds a flag.

$ cat extractions/sequence_2.bin.extracted/2710/flag.txt
v1t{30877432d1026706d7e805da846a32c3}
```