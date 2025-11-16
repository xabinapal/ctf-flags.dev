(function() {
  'use strict';
  
  const xorInputAscii = document.getElementById('xor-input-ascii');
  const xorInputHex = document.getElementById('xor-input-hex');
  const xorKeyAscii = document.getElementById('xor-key-ascii');
  const xorKeyHex = document.getElementById('xor-key-hex');
  const xorOutputAscii = document.getElementById('xor-output-ascii');
  const xorOutputHex = document.getElementById('xor-output-hex');
  
  if (!xorInputAscii) return;
  
  let updating = false;
  
  function parseHex(hexStr) {
    if (!hexStr.trim()) return null;
    const hex = hexStr.replace(/\s/g, '');
    if (!/^[0-9A-Fa-f]+$/.test(hex)) throw new Error('Invalid hex');
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
  }
  
  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join(' ');
  }
  
  function bytesToAscii(bytes) {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }
  
  function xorBytes(inputBytes, keyBytes) {
    if (!keyBytes || keyBytes.length === 0) return new Uint8Array(0);
    
    const result = new Uint8Array(inputBytes.length);
    for (let i = 0; i < inputBytes.length; i++) {
      result[i] = inputBytes[i] ^ keyBytes[i % keyBytes.length];
    }
    return result;
  }
  
  function updateXOR(editedField) {
    if (updating) return;
    updating = true;
    
    try {
      // Handle input field updates (sync ASCII and HEX)
      if (editedField === 'input-ascii') {
        const text = xorInputAscii.value;
        const bytes = new TextEncoder().encode(text);
        if (xorInputHex) xorInputHex.value = bytesToHex(bytes);
      } else if (editedField === 'input-hex') {
        const hex = xorInputHex.value;
        try {
          const bytes = parseHex(hex);
          if (bytes && xorInputAscii) {
            xorInputAscii.value = bytesToAscii(bytes);
          }
        } catch (e) {
          // Invalid hex, don't update ASCII
        }
      }
      
      // Handle key field updates (sync ASCII and HEX)
      if (editedField === 'key-ascii') {
        const text = xorKeyAscii.value;
        const bytes = new TextEncoder().encode(text);
        if (xorKeyHex) xorKeyHex.value = bytesToHex(bytes);
      } else if (editedField === 'key-hex') {
        const hex = xorKeyHex.value;
        try {
          const bytes = parseHex(hex);
          if (bytes && xorKeyAscii) {
            xorKeyAscii.value = bytesToAscii(bytes);
          }
        } catch (e) {
          // Invalid hex, don't update ASCII
        }
      }
      
      // Get input bytes (prefer the one that was just edited, or ASCII if available)
      let inputBytes = null;
      if (editedField === 'input-hex' && xorInputHex.value.trim()) {
        inputBytes = parseHex(xorInputHex.value);
      } else if (xorInputAscii.value.trim()) {
        inputBytes = new TextEncoder().encode(xorInputAscii.value);
      } else if (xorInputHex.value.trim()) {
        inputBytes = parseHex(xorInputHex.value);
      }
      
      // Get key bytes (prefer the one that was just edited, or ASCII if available)
      let keyBytes = null;
      if (editedField === 'key-hex' && xorKeyHex.value.trim()) {
        keyBytes = parseHex(xorKeyHex.value);
      } else if (xorKeyAscii.value.trim()) {
        keyBytes = new TextEncoder().encode(xorKeyAscii.value);
      } else if (xorKeyHex.value.trim()) {
        keyBytes = parseHex(xorKeyHex.value);
      }
      
      if (!inputBytes || inputBytes.length === 0 || !keyBytes || keyBytes.length === 0) {
        if (xorOutputAscii) xorOutputAscii.value = '';
        if (xorOutputHex) xorOutputHex.value = '';
        updating = false;
        return;
      }
      
      // Perform XOR
      const resultBytes = xorBytes(inputBytes, keyBytes);
      
      // Update output fields
      if (xorOutputAscii) xorOutputAscii.value = bytesToAscii(resultBytes);
      if (xorOutputHex) xorOutputHex.value = bytesToHex(resultBytes);
    } catch (e) {
      if (xorOutputAscii) xorOutputAscii.value = 'Error: ' + e.message;
      if (xorOutputHex) xorOutputHex.value = 'Error: ' + e.message;
    }
    
    updating = false;
  }
  
  xorInputAscii.addEventListener('input', () => updateXOR('input-ascii'));
  if (xorInputHex) xorInputHex.addEventListener('input', () => updateXOR('input-hex'));
  if (xorKeyAscii) xorKeyAscii.addEventListener('input', () => updateXOR('key-ascii'));
  if (xorKeyHex) xorKeyHex.addEventListener('input', () => updateXOR('key-hex'));
})();
