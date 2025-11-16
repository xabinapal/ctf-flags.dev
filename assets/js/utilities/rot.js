(function() {
  'use strict';
  
  const rotPlaintext = document.getElementById('rot-plaintext');
  const rotRotn = document.getElementById('rot-rotn');
  const rotRot47 = document.getElementById('rot-rot47');
  const rotRot8000 = document.getElementById('rot-rot8000');
  const rotN = document.getElementById('rot-n');
  
  if (!rotPlaintext) return;
  
  let updating = false;

  function rotN_func(str, n) {
    return str.replace(/[a-zA-Z]/g, (c) => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode((c.charCodeAt(0) - base + n) % 26 + base);
    });
  }

  function rot47(str) {
    return str.replace(/[!-~]/g, (c) => {
      const code = c.charCodeAt(0);
      return String.fromCharCode((code - 33 + 47) % 94 + 33);
    });
  }

  function rot8000(str) {
    // ROT8000: Rotation by 31753 (0x7C09) on Basic Multilingual Plane
    // Works on BMP (0x0000-0xFFFF) excluding control characters
    // Shift is approximately 0x8000 but adjusted to 0x7C09
    // Since it's half the BMP, encryption = decryption (self-inverse)
    // Ignored: U+0000-U+001F, U+007F-U+00A0, U+D800-U+DFFF, and spaces (U+0020)
    const shift = 0x7C09; // 31753
    
    function isIgnored(code) {
      // Space and space variants
      if (code === 0x20) return true;
      // Control characters U+0000 to U+001F
      if (code >= 0x0000 && code <= 0x001F) return true;
      // Control characters U+007F to U+00A0
      if (code >= 0x007F && code <= 0x00A0) return true;
      // Surrogate pairs U+D800 to U+DFFF
      if (code >= 0xD800 && code <= 0xDFFF) return true;
      return false;
    }
    
    return str.replace(/./gu, (c) => {
      const code = c.codePointAt(0);
      // Only process characters in BMP (0x0000-0xFFFF)
      if (code > 0xFFFF) return c;
      
      // Ignore specified characters (return as-is)
      if (isIgnored(code)) return c;
      
      // Apply rotation: code + 0x7C09
      let rotated = code + shift;
      
      // Wrap around if exceeds BMP
      if (rotated > 0xFFFF) {
        rotated -= 0x10000;
      }
      
      // Skip ignored characters in result
      while (isIgnored(rotated)) {
        rotated += 0x10000;
        if (rotated > 0xFFFF) {
          rotated -= 0x10000;
          break;
        }
      }
      
      // Ensure we stay in valid BMP range
      if (rotated >= 0 && rotated <= 0xFFFF && !isIgnored(rotated)) {
        return String.fromCodePoint(rotated);
      }
      return c;
    });
  }

  function updateROT(editedField) {
    if (updating) return;
    updating = true;
    
    try {
      if (editedField === 'plaintext') {
        const plaintext = rotPlaintext.value;
        const n = parseInt(rotN?.value || '13') || 13;
        if (rotRotn) rotRotn.value = rotN_func(plaintext, n);
        if (rotRot47) rotRot47.value = rot47(plaintext);
        if (rotRot8000) rotRot8000.value = rot8000(plaintext);
      } else if (editedField === 'rotn') {
        const n = parseInt(rotN?.value || '13') || 13;
        const plaintext = rotN_func(rotRotn.value, (26 - n) % 26);
        rotPlaintext.value = plaintext;
        if (rotRot47) rotRot47.value = rot47(plaintext);
        if (rotRot8000) rotRot8000.value = rot8000(plaintext);
      } else if (editedField === 'rot47') {
        const plaintext = rot47(rotRot47.value);
        rotPlaintext.value = plaintext;
        const n = parseInt(rotN?.value || '13') || 13;
        if (rotRotn) rotRotn.value = rotN_func(plaintext, n);
        if (rotRot8000) rotRot8000.value = rot8000(plaintext);
      } else if (editedField === 'rot8000') {
        const plaintext = rot8000(rotRot8000.value);
        rotPlaintext.value = plaintext;
        const n = parseInt(rotN?.value || '13') || 13;
        if (rotRotn) rotRotn.value = rotN_func(plaintext, n);
        if (rotRot47) rotRot47.value = rot47(plaintext);
      } else if (editedField === 'n') {
        if (rotPlaintext.value) {
          updateROT('plaintext');
        } else if (rotRotn && rotRotn.value) {
          updateROT('rotn');
        }
      }
    } catch (e) {
      // Error
    }
    
    updating = false;
  }

  rotPlaintext.addEventListener('input', () => updateROT('plaintext'));
  if (rotRotn) rotRotn.addEventListener('input', () => updateROT('rotn'));
  if (rotRot47) rotRot47.addEventListener('input', () => updateROT('rot47'));
  if (rotRot8000) rotRot8000.addEventListener('input', () => updateROT('rot8000'));
  if (rotN) {
    rotN.addEventListener('input', () => updateROT('n'));
    rotN.style.display = 'inline-block';
  }
})();
