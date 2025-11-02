---
title: reto10
challenge_type: Forensics
difficulty: Medium
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  Help me review this access log that looks like the flag is hidden somewhere.
attachments:
  - title: access.log
    url: /assets/files/navarra-cyber-talent-25-4/reto10/access.log
---

## Recon

A quick inspection of the first few lines of the access log file revealed typical Apache/Nginx log entries with random-looking paths consisting of 10 alphanumeric characters:

```
175.242.26.220 - [17/Oct/2025:11:56:54 +0000] "PUT /yitg495ISZ" HTTP/1.1 200 - "curl/8.1.2"
16.11.231.140 - [17/Oct/2025:11:56:54 +0000] "GET /gtJ5ofYedq" HTTP/1.1 200 - "Mozilla/5.0 ..."
74.102.133.55 - [17/Oct/2025:11:56:54 +0000] "GET /xomCa8FfQ6" HTTP/1.1 200 - "Mozilla/5.0 ..."
192.156.131.1 - [17/Oct/2025:11:56:54 +0000] "PUT /ATPT1td9vo" HTTP/1.1 200 - "Wget/1.21.4"
```

Next, I searched the log for any recognizable flag characters:

```bash
$ grep -F -e '{' -e '}' access.log
201.96.114.59 - [17/Oct/2025:11:57:03 +0000] "PUT /{" HTTP/1.1 200 - "Mozilla/5.0 ..."
1.86.243.109 - [17/Oct/2025:11:57:35 +0000] "PUT /}" HTTP/1.1 200 - "Wget/1.21.4"
```

It appears that among the thousands of normal log entries with multi-character paths, some entries contain request paths with only a single character, and these characters form the flag.

## Exploitation

To accurately extract all the characters, I wrote a Python script:

```python
import re

with open('access.log', 'r') as f:
    lines = f.readlines()

# Pattern to match single-character paths
pattern = r'".+ /([^/])"'

flag = ""
for line in lines:
    m = re.search(pattern, line)
    if m:
       flag += m.group(1)

print("Flag:", flag)
```

## Flag capture

Executing the script will display the extracted flag:

```bash
$ python3 extract_flag.py
Flag: conclave{55a164e14ab73d3caa28a11dc2f91fdc}
```
