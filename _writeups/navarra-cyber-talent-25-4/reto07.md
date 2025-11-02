---
title: reto07
challenge_type: Forensics
difficulty: Easy
author: "@lassault"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  Someone has accessed our server and stolen sensitive information. Can you find any clues?
attachments:
  - title: fl4g_1n_th3_w1r3s.pcap
    url: /assets/files/navarra-cyber-talent-25-4/reto07/fl4g_1n_th3_w1r3s.pcap
---

## Recon

After downloading the PCAP file, we observe that it contains `1,210` packets captured over a period of approximately `8.7` seconds, indicating a relatively short network session.

```
$ capinfos fl4g_1n_th3_w1r3s.pcap
Number of packets:   1,210
File size:           1,317 kB
Capture duration:    8.731007 seconds
Earliest packet time: 2025-10-20 08:54:50.483775
Latest packet time:   2025-10-20 08:54:59.214782
```

By examining the protocol hierarchy statistics, we discovered the presence of FTP traffic:

```bash
$ tshark -r fl4g_1n_th3_w1r3s.pcap -q -z io,phs
======================================
Protocol Hierarchy Statistics
Filter:

eth          frames:1210 bytes:1298390
  ip         frames:1202 bytes:1298054
    tcp      frames:894 bytes:1256138
      ftp    frames:25 bytes:2276
======================================
```

## Exploitation

FTP is notorious for transmitting authentication credentials in plaintext. Since the protocol does not encrypt user information, it is straightforward to extract credentials from traffic captures.

## Flag capture (the hard way)

To extract the FTP conversation and identify the compromised credentials, we can use `tshark` with display filters that focus on FTP protocol messages:

```bash
$ tshark -r fl4g_1n_th3_w1r3s.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg | grep -E ^PASS
PASS	conclave{d705b625cd50914c33979813e9ae7b4d}
```

## Flag capture (the easy way)

Alternatively, by searching for the known flag prefix `conclave` in Wireshark, we can quickly locate and retrieve the flag.

![Wireshark search](/assets/files/navarra-cyber-talent-25-4/reto07/flag.png)