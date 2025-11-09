---
title: Risky Chain
challenge_type: Misc
author: "@vielite"
writeup_author: "@xabito"
competition: infobahn-ctf-2025
summary: |-
  Metal to the future!
connections:
  - url: riskychain.challs.infobahnc.tf:1337
attachments:
  - title: risc-v
    url: /assets/files/infobahn-ctf-2025/risky-chain/risc-v
---

## Recon

We're given access to a remote service that acts like a simplified blockchain. When we connect, it shows us a genesis block and asks us to submit a new block. To do so, we need to provide a nonce and a **RISC-V** assembly contract. If our block is accepted, the server will execute our RISC-V code.

```
$ nc riskychain.challs.infobahnc.tf 1337
A new block has been mined! If its valid, its RISC-V contract will be executed.

--- Block 0 ---
Timestamp:  1763107355
Prev Hash:  0
Nonce:      0x3039
Hash:       397266e738f09b6e6407f4fd67c78891ea212c34ce866bd50da649c13f08c0d7
RISC-V Data (64 bytes)
------------------
Submit your new block's data.
Nonce (as hex): 0x3039
Enter your RISC-V assembly contract (end with a blank line):
nop

[!] Unknown instruction: nop
[-] Assembly failed. Rejecting block.
```

## Exploitation

Opening the binary in Ghidra gives us a clear view of its workflow. The `main` function computes the hash for each block, then calls `is_block_valid` to see if the block meets the chain’s requirements. If the block is accepted, the server executes our RISC-V contract.

![Ghidra main function decompilation](/assets/files/infobahn-ctf-2025/risky-chain/ghidra_1.png)

This challenge boils down to two key questions: how can we create a valid block, and how does running a RISC-V contract help us obtain the flag? To answer the first question, let's dig into the `is_block_valid` function:

![Ghidra is_block_valid function decompilation](/assets/files/infobahn-ctf-2025/risky-chain/ghidra_2.png)

I noticed something odd: there is actually a backdoor. The very first conditional checks if the nonce is `0xdeadbeef`. If it is, the block is immediately considered valid.

To answer the second question, we need to examine the `execute_rv_code` function to see how it operates. This function works as a lightweight RISC-V interpreter, and at some point it calls another function named `ecall_handler`, which appears to be responsible for printing the flag.

![Ghidra ecall_handler function decompilation](/assets/files/infobahn-ctf-2025/risky-chain/ghidra_3.png)

Honestly, this is a lot to analyze in the middle of a CTF, so let's open our secret weapon: **ChatGPT**.

> `execute_rv_code` implements a very small RISC-V interpreter that operates on up to 64 bytes of machine code. It initializes a register file of 32 integer registers to zero and then sequentially reads instructions from the provided memory buffer. Only two instructions are supported: `ADDI` (an integer add with an immediate value) and `ECALL`.
>
> The `ECALL` instruction triggers a call to `ecall_handler`, which receives a pointer to the register file. The handler examines register `x10`, located at offset `0x28` within the register array. If the value of this register is exactly `0x539` (decimal `1337`), the handler treats it as a special syscall and prints the challenge flag.

To solve the challenge, we simply neded to set register `x10` to `1337` and then run `ECALL`. This is straighforward because all registers start at zero, so we can use any of them to load the expected value.

```
addi x10, x0, 1337
ecall
```

## Flag capture

To get the flag, simply use the backdoor nonce together with the RISC-V code we prepared:

```
$ nc riskychain.challs.infobahnc.tf 1337

A new block has been mined! If its valid, its RISC-V contract will be executed.

--- Block 0 ---
Timestamp:  1763582603
Prev Hash:  0
Nonce:      0x3039
Hash:       795eec4a6060bc623ee29bff31537d64f5a4664c2aad7dc4d44095a2c9c8a883
RISC-V Data (64 bytes)
------------------
Submit your new block's data.
Nonce (as hex): 0xdeadbeef
Enter your RISC-V assembly contract (end with a blank line):
addi x10, x10, 1337
ecall

[+] Assembled 8 bytes of machine code.
[+] Block is valid! Adding to chain.

--- Block 1 ---
Timestamp:  1763582603
Prev Hash:  795eec4a6060bc623ee29bff31537d64f5a4664c2aad7dc4d44095a2c9c8a883
Nonce:      0xdeadbeef
Hash:       323008b63dc6d3bf92da6003175c6efe94aadd2aa36e790f76cb1c549f33de94
RISC-V Data (64 bytes)
------------------
[*] Starting RISC-V execution...
ECALL 1337: Nice! Here's your flag!
infobahn{Th3_futur3_15_m3t4l1c_4nd_RISC-V}
[*] Execution finished.
```

{% include writeups/img-50.html %}