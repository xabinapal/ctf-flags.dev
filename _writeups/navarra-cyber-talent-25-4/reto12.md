---
title: reto12
challenge_type: Misc
difficulty: Medium
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  The flag is stored on a network that we can access via SSH. There are several computers on the network, all of which are on the same subnet. All computers have an SSH server and a web page, but only one of them has the flag. It seems that you cannot open a terminal.
connections:
  - url: ssh://nct25.thehackerconclave.es:26012
    descroption: |-
      Username: dummy
      Password: dummy
---

## Recon

First, let’s check if we can establish a connection to the SSH port as described in the challenge:

```bash
$ ssh dummy@nct25.thehackerconclave.es -p 26012
The authenticity of host '[nct25.thehackerconclave.es]:26012 ([130.206.158.156]:26012)' can't be established.
ED25519 key fingerprint is: SHA256:UXHTE7oFEsIMiM5v8iyS6z9KSLhfBZSMA+GDlrAXIoM
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
dummy@nct25.thehackerconclave.es's password: dummy
Connection to nct25.thehackerconclave.es closed.
```

The session closed immediately after authentication. This indicated that, while the server accepted our credentials, it did not permit interactive shell access. However, SSH can still be useful even without shell access.

The next logical step was to check if SSH port forwarding was permitted. By using the `-N` (no remote command) and `-D` (dynamic SOCKS proxy) options, we executed the following command:

```bash
$ ssh -N -D 1080 dummy@nct25.thehackerconclave.es -p 26012
dummy@nct25.thehackerconclave.es's password: dummy
```

The connection remained open, confirming that dynamic port forwarding was enabled. By configuring `127.0.0.1:1080` as a SOCKS5 proxy, we were now able to access internal network services. To begin, we checked the web page referenced in the challenge description:

```bash
curl --socks5 127.0.0.1:1080 http://127.0.0.1:80
```

The response is an HTML file displaying the message: `Hello World FROM 192.168.6.5 THIS_IS_NOT_A_FLAG`. This reveals helpful information about the network, suggesting that the local subnet is likely `192.168.6.0/24`.

## Exploitation

We will use `proxychains` to perform a network scan through the SOCKS proxy. Here is a straightforward configuration:

```bash
$ cat > proxychains.conf << EOF
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080
EOF
```

After executing an `nmap` scan, we determined that SSH access is available on another server:

```bash
$ proxychains4 -q -f proxychains.conf nmap 192.168.6.0/24 -p 22
Nmap scan report for 192.168.6.3
Host is up (0.00s latency).

PORT   STATE SERVICE
22/tcp open  ssh
```

This challenge resembles a matryoshka doll, with each layer revealing another. By accessing the next host via SSH port forwarding, we can reach its web server to check for the flag.

If the flag is not found there, we must use this newly accessed server as a pivot point—setting up an additional proxy—to continue progressing through the network.

To connect to another server's SSH service through the existing proxy, we once again use `proxychains`:

```bash
$ proxychains4 -q -f proxychains.conf ssh -N -D 1081 dummy@192.168.6.3 -p 22
dummy@192.168.6.3's password:

$ curl --socks5 127.0.0.1:1081 http://127.0.0.1:80
Hello World FROM 192.168.6.3 THIS_IS_NOT_A_FLAG
```
## Flag Capture

After considerable effort, we successfully identified the full sequence of hosts necessary to reach the web server containing the flag:

```
Local Machine
  → SOCKS5 1080 → nct25.thehackerconclave.es:26012
    Hello World FROM 192.168.6.5 THIS_IS_NOT_A_FLAG

      → SOCKS5 1081 → 192.168.6.3
        Hello World FROM 192.168.6.3 THIS_IS_NOT_A_FLAG

          → SOCKS5 1082 → 192.168.6.7
            Hello World FROM 192.168.6.7 THIS_IS_NOT_A_FLAG

              → SOCKS5 1083 → 192.168.6.4
                Hello World FROM 192.168.6.4 THIS_IS_NOT_A_FLAG

                  → SOCKS5 1084 → 192.168.6.6
                    Hello World FROM 192.168.6.6 THIS_IS_NOT_A_FLAG
                    
                      → SOCKS5 1085 → 192.168.6.2
```

At last, upon reaching `192.168.6.2`, we discover the flag:

```bash
$ curl --socks5 127.0.0.1:1085 http://127.0.0.1:80
conclave{4b05724739d1cef33c16596814910c0f}
```