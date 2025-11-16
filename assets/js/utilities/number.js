(function() {
  'use strict';
  
  const numBase2 = document.getElementById('num-base2');
  const numBase8 = document.getElementById('num-base8');
  const numBase10 = document.getElementById('num-base10');
  const numBase16 = document.getElementById('num-base16');
  const numAscii = document.getElementById('num-ascii');
  
  if (!numBase2) return;
  
  let updating = false;

  function convertBase(str, fromBase, toBase) {
    if (!str) return '';
    try {
      let num = BigInt(0);
      const digits = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      
      for (let char of str.toUpperCase().replace(/\s/g, '')) {
        const digit = digits.indexOf(char);
        if (digit === -1 || digit >= fromBase) throw new Error('Invalid digit');
        num = num * BigInt(fromBase) + BigInt(digit);
      }
      
      if (num === 0n) return '0';
      let result = '';
      while (num > 0n) {
        result = digits[Number(num % BigInt(toBase))] + result;
        num = num / BigInt(toBase);
      }
      return result;
    } catch (e) {
      throw e;
    }
  }

  function updateNumberBase(editedField) {
    if (updating) return;
    updating = true;
    
    try {
      let numDecimal = null;
      
      if (editedField === 'base2') {
        const val = numBase2.value.replace(/\s/g, '');
        if (!val) {
          if (numBase8) numBase8.value = '';
          if (numBase10) numBase10.value = '';
          if (numBase16) numBase16.value = '';
          if (numAscii) numAscii.value = '';
          updating = false;
          return;
        }
        numDecimal = convertBase(val, 2, 10);
      } else if (editedField === 'base8') {
        const val = numBase8.value.replace(/\s/g, '');
        if (!val) {
          if (numBase2) numBase2.value = '';
          if (numBase10) numBase10.value = '';
          if (numBase16) numBase16.value = '';
          if (numAscii) numAscii.value = '';
          updating = false;
          return;
        }
        numDecimal = convertBase(val, 8, 10);
      } else if (editedField === 'base10') {
        const val = numBase10.value.replace(/\s/g, '');
        if (!val) {
          if (numBase2) numBase2.value = '';
          if (numBase8) numBase8.value = '';
          if (numBase16) numBase16.value = '';
          if (numAscii) numAscii.value = '';
          updating = false;
          return;
        }
        numDecimal = val;
      } else if (editedField === 'base16') {
        const val = numBase16.value.replace(/\s/g, '');
        if (!val) {
          if (numBase2) numBase2.value = '';
          if (numBase8) numBase8.value = '';
          if (numBase10) numBase10.value = '';
          if (numAscii) numAscii.value = '';
          updating = false;
          return;
        }
        numDecimal = convertBase(val, 16, 10);
      } else if (editedField === 'ascii') {
        const text = numAscii.value;
        if (!text) {
          if (numBase2) numBase2.value = '';
          if (numBase8) numBase8.value = '';
          if (numBase10) numBase10.value = '';
          if (numBase16) numBase16.value = '';
          updating = false;
          return;
        }
        const bytes = [];
        for (let char of text) {
          bytes.push(char.charCodeAt(0));
        }
        let num = BigInt(0);
        for (let byte of bytes) {
          num = num * 256n + BigInt(byte);
        }
        numDecimal = num.toString();
      }
      
      if (numDecimal !== null) {
        if (editedField !== 'base2' && numBase2) {
          numBase2.value = convertBase(numDecimal, 10, 2);
        }
        if (editedField !== 'base8' && numBase8) {
          numBase8.value = convertBase(numDecimal, 10, 8);
        }
        if (editedField !== 'base10' && numBase10) {
          numBase10.value = numDecimal;
        }
        if (editedField !== 'base16' && numBase16) {
          numBase16.value = convertBase(numDecimal, 10, 16).toUpperCase();
        }
        if (editedField !== 'ascii' && numAscii) {
          try {
            const numBigInt = BigInt(numDecimal);
            const bytes = [];
            let temp = numBigInt;
            while (temp > 0n) {
              bytes.unshift(Number(temp % 256n));
              temp = temp / 256n;
            }
            let ascii = '';
            for (let byte of bytes) {
              ascii += String.fromCharCode(byte);
            }
            numAscii.value = ascii;
          } catch (e) {
            numAscii.value = '';
          }
        }
      }
    } catch (e) {
      // Error
    }
    
    updating = false;
  }

  numBase2.addEventListener('input', () => updateNumberBase('base2'));
  if (numBase8) numBase8.addEventListener('input', () => updateNumberBase('base8'));
  if (numBase10) numBase10.addEventListener('input', () => updateNumberBase('base10'));
  if (numBase16) numBase16.addEventListener('input', () => updateNumberBase('base16'));
  if (numAscii) numAscii.addEventListener('input', () => updateNumberBase('ascii'));
})();
