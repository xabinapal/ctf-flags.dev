---
title: reto09
challenge_type: Crypto
difficulty: Easy
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  We have a Ruby encoder. We have passed our flag through the encoder. See if you can figure out what it is.
attachments:
  - title: encoder.rb
    url: /assets/files/navarra-cyber-talent-25-4/reto09/encoder.rb
  - title: flag.txt
    url: /assets/files/navarra-cyber-talent-25-4/reto09/flag.txt
---

## Recon

The Ruby encoder applies the following sequence of transformations to each character:

1. `ch.ord`: get ASCII value of character
2. `<< 2`: left shift by 2 bits (multiply by 4)
3. `.to_s(10)`: convert to decimal string
4. `.to_i`: parse as integer
5. `.to_s(2)`: convert to binary string
6. `.rjust(12, '0')`: right-pad with `0` to 12 characters
7. `.ljust(14, '1')`: left-pad with `1` to 14 characters
8. `.join`: concatenate all chunks

The encoded output is 658 characters long. Since each original character is represented by 14 bits, this means the flag consists of `658 ÷ 14 = 47` characters.

The transformation chain can be simplified: steps 3 and 4 effectively do nothing (convert to string then back to integer), so the actual encoding is `ASCII value → multiply by 4 → convert to binary → pad to 12 bits → extend to 14 bits with trailing '1's`.

## Exploitation

To reverse the encoding, we need to work backwards through each transformation:

1. Split the encoded string into 14-bit chunks
2. Remove the last two `1` characters
3. Convert from binary to decimal
4. Divide by 4
5. Convert to ASCII character

To decode the flag, I wrote the following Python script:

```python
with open('flag.txt', 'r') as f:
    flag = f.read()

# 1. Split into 14-bit chunks
chunks = []
for i in range(0, len(flag), 14):
    chunk = flag[i:i+14]
    if len(chunk) == 14:
        chunks.append(chunk)

# Process each chunk
decoded = []
for chunk in chunks:
    binary_12bit = chunk[:12]
    decimal_value = int(binary_12bit, 2)
    ascii_value = decimal_value // 4
    char = chr(ascii_value)
    decoded.append(char)

# Decode the flag
flag = ''.join(decoded)
print(f"Flag: {flag}")
```

## Flag capture

Running the script will output the decoded flag:

```bash
$ python3 extract_flag.py
Flag: conclave{5d896b6acd552a92ccea9f6bc701370d}
```
