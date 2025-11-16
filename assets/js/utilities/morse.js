(function() {
  'use strict';
  
  const morsePlaintext = document.getElementById('morse-plaintext');
  const morseEncoded = document.getElementById('morse-encoded');
  
  if (!morsePlaintext) return;
  
  let updating = false;

  const morseCode = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....',
    'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.',
    'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--',
    '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...',
    ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.',
    '$': '...-..-', '@': '.--.-.'
  };

  const morseReverse = {};
  for (let [char, code] of Object.entries(morseCode)) {
    morseReverse[code] = char;
  }

  function updateMorse(editedField) {
    if (updating) return;
    updating = true;
    
    try {
      if (editedField === 'plaintext') {
        const text = morsePlaintext.value.toUpperCase();
        let result = '';
        for (let char of text) {
          if (char === ' ') {
            result += '/ ';
          } else if (morseCode[char]) {
            result += morseCode[char] + ' ';
          } else {
            result += char + ' ';
          }
        }
        if (morseEncoded) morseEncoded.value = result.trim();
      } else {
        const codes = morseEncoded.value.trim().split(/\s+/);
        let result = '';
        for (let code of codes) {
          if (code === '/') {
            result += ' ';
          } else if (morseReverse[code]) {
            result += morseReverse[code];
          } else {
            result += code;
          }
        }
        morsePlaintext.value = result;
      }
    } catch (e) {
      if (editedField === 'plaintext') {
        if (morseEncoded) morseEncoded.value = 'Error: ' + e.message;
      } else {
        morsePlaintext.value = 'Error: ' + e.message;
      }
    }
    
    updating = false;
  }

  morsePlaintext.addEventListener('input', () => updateMorse('plaintext'));
  if (morseEncoded) morseEncoded.addEventListener('input', () => updateMorse('encoded'));
})();
