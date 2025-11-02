---
title: Lost Some Binary
challenge_type: Stego
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  SOS we lost some binary sir!
attachments:
  - title: Lost_Some_Binary.txt
    url: /assets/files/v1t-ctf-2025/lost-some-binary/Lost_Some_Binary.txt
---

## Recon

If we convert each 8-bit sequence from the file to its corresponding ASCII character, we obtain:

```
Hiii man,how r u ?Is it :))))Rawr-^^[]  LSB{><}!LSB~~LSB~~---v1t  {135900_13370}
```

The presence of multiple `LSB` markers within the message suggests that we should perform **Least Significant Bit** extraction. Additionally, the challenge title itself references LSB, further reinforcing this hint.

## Flag capture

To solve this challenge, we need to extract the **least significant bit** from every 8-bit group in the provided binary data and use those bits to reconstruct the flag as ASCII text. A convenient way to perform this operation is by using this [CyberChef](https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Regex','string':'%5B01%5D%7B7%7D(%5B01%5D)'%7D,'$1',true,false,true,false)From_Binary('Space',8)&input=MDEwMDEwMDAgMDExMDEwMDEgMDExMDEwMDEgMDExMDEwMDEgMDAxMDAwMDAgMDExMDExMDEgMDExMDAwMDEgMDExMDExMTAgMDAxMDExMDAgMDExMDEwMDAgMDExMDExMTEgMDExMTAxMTEgMDAxMDAwMDAgMDExMTAwMTAgMDAxMDAwMDAgMDExMTAxMDEgMDAxMDAwMDAgMDAxMTExMTEgMDEwMDEwMDEgMDExMTAwMTEgMDAxMDAwMDAgMDExMDEwMDEgMDExMTAxMDAgMDAxMDAwMDAgMDAxMTEwMTAgMDAxMDEwMDEgMDAxMDEwMDEgMDAxMDEwMDEgMDAxMDEwMDEgMDEwMTAwMTAgMDExMDAwMDEgMDExMTAxMTEgMDExMTAwMTAgMDAxMDExMDEgMDEwMTExMTAgMDEwMTExMTAgMDEwMTEwMTEgMDEwMTExMDEgMDAxMDAwMDAgMDAxMDAwMDAgMDEwMDExMDAgMDEwMTAwMTEgMDEwMDAwMTAgMDExMTEwMTEgMDAxMTExMTAgMDAxMTExMDAgMDExMTExMDEgMDAxMDAwMDEgMDEwMDExMDAgMDEwMTAwMTEgMDEwMDAwMTAgMDExMTExMTAgMDExMTExMTAgMDEwMDExMDAgMDEwMTAwMTEgMDEwMDAwMTAgMDExMTExMTAgMDExMTExMTAgMDAxMDExMDEgMDAxMDExMDEgMDAxMDExMDEgMDExMTAxMTAgMDAxMTAwMDEgMDExMTAxMDAgMDAxMDAwMDAgMDAxMDAwMDAgMDExMTEwMTEgMDAxMTAwMDEgMDAxMTAwMTEgMDAxMTAxMDEgMDAxMTEwMDEgMDAxMTAwMDAgMDAxMTAwMDAgMDEwMTExMTEgMDAxMTAwMDEgMDAxMTAwMTEgMDAxMTAwMTEgMDAxMTAxMTEgMDAxMTAwMDAgMDExMTExMDE&oeol=VT) recipe.

```
Flag: v1t{LSB:>}
```
