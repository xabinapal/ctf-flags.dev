---
title: reto08
challenge_type: Stego
difficulty: Easy
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  A psychophony may hide more than meets the eye.
attachments:
  - title: audio.wav
    url: /assets/files/navarra-cyber-talent-25-4/reto08/audio.wav
---

## Recon

The challenge description suggests that there may be steganography hidden within the audio file. The primary technique for solving this challenge is **spectrogram analysis**. A spectrogram displays the frequency spectrum of the audio over time, and information can be concealed by embedding visual patterns within specific frequency ranges.


## Flag capture

I opened the audio file in `Audacity` and switched to the spectrogram view. The flag was immediately visible to the naked eye:

![Spectrogram analysis](/assets/files/navarra-cyber-talent-25-4/reto08/flag.png)

There was an issue with the challenge: the spectrogram did not display the entire flag. Nevertheless, the partial flag was accepted as the correct answer.

```
Flag: ve{6d60783c4c7c4b277e55a3405ff6
```
