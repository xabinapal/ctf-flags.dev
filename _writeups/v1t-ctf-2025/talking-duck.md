---
title: Talking Duck
challenge_type: Stego
author: "@Rawr"
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  Bro this duck is talking to me or something? I'm high or what??
attachments:
  - title: duck_sound.wav
    url: /assets/files/v1t_ctf_2025/talking_duck/duck_sound.wav
---

## Recon

Upon listening to the file, it sounds like the duck is making "short" and "long" quacks. This immediately suggested Morse code to me. To analyze this further, I opened the audio file in Audacity and used the spectrogram view to visually interpret the signal.

![Spectrogram analysis](/assets/files/v1t-ctf-2025/talking-duck/spectrogram.png)

## Flag capture

By translating the pulses into Morse code, we obtain the following sequence:

```
...- / .---- / - / -.. / ..- / -.-. / -.- / ... / ----- / ... / ... / ----- / ...
```

Decoding that sequence using any Morse tool reveals the message: `V1TDUCKS0SS0S`.

```
Flag: V1T{DUCK_S0S_S0S}
```
