---
title: zipbomb
challenge_type: Misc
writeup_author: "@xabito"
competition: lakectf-25-26-quals
summary: |-
  Have you thought about maybe downloading more RAM? I've heard it helps you get to the bottom of things.
attachments:
  - title: bomb.zip
    url: /assets/files/lakectf-25-26-quals/zipbomb/bomb.zip
---

## Recon

Based on the challenge name, it is likely that the ZIP file contains another ZIP inside, and this process repeats with additional files until we eventually find the flag. Running binwalk confirms that the file is structured in this way:

```bash
$ binwalk -e bomb.zip
bomb.zip
------------------------------------------------------------------------------------
DECIMAL      HEXADECIMAL      DESCRIPTION
------------------------------------------------------------------------------------
0            0x0              ZIP archive, file count: 2, total size: 279658 bytes
------------------------------------------------------------------------------------
[+] Extraction of zip data at offset 0x0 completed successfully
------------------------------------------------------------------------------------
Analyzed 1 file for 85 file signatures (187 magic patterns) in 22.0 milliseconds

$ ls -e extractions/bomb.zip.extracted/0
nosyawur.txt tuwebvif.zip

$ cat extractions/bomb.zip.extracted/0/nosyawur.txt
DOWNLOAD MORE RAM DOWNLOAD MORE RAM DOWNLOAD MORE RAM ...

$ binwalk -e extractions/bomb.zip.extracted/0/tuwebvif.zip
extractions/bomb.zip.extracted/0/tuwebvif.zip
------------------------------------------------------------------------------------
DECIMAL      HEXADECIMAL      DESCRIPTION
------------------------------------------------------------------------------------
0            0x0              ZIP archive, file count: 2, total size: 279342 bytes
------------------------------------------------------------------------------------
[+] Extraction of zip data at offset 0x0 completed successfully
------------------------------------------------------------------------------------
Analyzed 1 file for 85 file signatures (187 magic patterns) in 21.0 milliseconds

$ ls -e extractions/tuwebvif.zip.extracted/0/
bjqqrwjy.zip lgnrleau.txt
```

## Exploitation

Extracting each layer by hand would quickly become very time-consuming unless you want to spend your entire day on it. A much better approach is to automate the process with a script. Just remember two key things: do not use recursion, and try to avoid creating nested directory layouts.

```bash
while true; do
    binwalk -e bomb.zip;
    if ! ls extractions/bomb.zip.extracted/0/*.zip; then
        break;
    fi;

    mv extractions/bomb.zip.extracted/0/*.zip bomb.zip;
    rm -rf extractions;
done
```

## Flag capture

Once we finish extracting each layer one by one, we will eventually reach the flag:

```bash
$ ls extractions/bomb.zip.extracted/0/
flag.txt

$ cat extractions/bomb.zip.extracted/0/flag.txt
EPFL{m4yb3_TH3_r3A1_r4M_15_th3_Fr13nd5_w3_m4d3_410ng_th3_w4y}
```