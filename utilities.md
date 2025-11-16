---
layout: default
title: Utilities
summary: Interactive utilities and helpers for CTF players. Access quick tools and essential helpers for puzzles and challenges, cybersecurity competitions, and infosec problem-solving.
permalink: /utilities/
---

<section class="hero">
  <h1>flag{ut1l1t13s}</h1>
  <p>
    Interactive utilities and helpers for CTF players. Access quick tools and essential helpers for puzzles and challenges, cybersecurity competitions, and infosec problem-solving.
  </p>
</section>

<section class="utilities-section">
  <div class="utility-selector">
    <button class="utility-chip active" data-utility="number">Number</button>
    <button class="utility-chip" data-utility="base">Base</button>
    <button class="utility-chip" data-utility="url">URL</button>
    <button class="utility-chip" data-utility="rot">ROT</button>
    <button class="utility-chip" data-utility="xor">XOR</button>
    <button class="utility-chip" data-utility="morse">Morse</button>
    <button class="utility-chip" data-utility="timestamp">Timestamp</button>
    <button class="utility-chip" data-utility="jwt">JWT</button>
  </div>
  
  <div id="utility-container" class="utility-container">
    <!-- Utilities will be loaded here dynamically -->
  </div>
</section>

<script src="{{ '/assets/js/utilities/loader.js' | relative_url }}"></script>
