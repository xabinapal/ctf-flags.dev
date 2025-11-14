---
layout: default
title: Utilities
summary: Interactive utilities and helpers for CTF players. Access quick tools and essential helpers for puzzles and challenges, cybersecurity competitions, and infosec problem-solving.
permalink: /utilities/
---

<section class="hero">
  <h1>flag{ut1l1t13s}</h1>
  <p class="summary">
    Interactive utilities and helpers for CTF players. Access quick tools and essential helpers for puzzles and challenges, cybersecurity competitions, and infosec problem-solving.
  </p>
</section>

<section class="section">
  <div class="selector">
    <button class="chip-rounded active" data-utility="number">Number</button>
    <button class="chip-rounded" data-utility="base">Base</button>
    <button class="chip-rounded" data-utility="url">URL</button>
    <button class="chip-rounded" data-utility="rot">ROT</button>
    <button class="chip-rounded" data-utility="xor">XOR</button>
    <button class="chip-rounded" data-utility="morse">Morse</button>
    <button class="chip-rounded" data-utility="timestamp">Timestamp</button>
    <button class="chip-rounded" data-utility="jwt">JWT</button>
  </div>
  
  <div id="utility-container">
    <!-- Utilities will be loaded here dynamically -->
  </div>
</section>

<script src="{{ '/assets/js/utilities/loader.js' | relative_url }}"></script>
