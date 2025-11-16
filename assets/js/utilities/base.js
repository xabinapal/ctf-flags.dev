(function() {
  'use strict';
  
  const basePlaintext = document.getElementById('base-plaintext');
  const baseBase32 = document.getElementById('base-base32');
  const baseBase45 = document.getElementById('base-base45');
  const baseBase58 = document.getElementById('base-base58');
  const baseBase62 = document.getElementById('base-base62');
  const baseBase64 = document.getElementById('base-base64');
  const baseBase85 = document.getElementById('base-base85');
  const baseBase92 = document.getElementById('base-base92');
  
  if (!basePlaintext) return;
  
  let updating = false;
  
  const baseEncoders = {
    base32: {
      alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
      encode: function(str) {
        if (!str) return '';
        const bytes = new TextEncoder().encode(str);
        let bits = '';
        for (let byte of bytes) {
          bits += byte.toString(2).padStart(8, '0');
        }
        while (bits.length % 5 !== 0) bits += '0';
        let result = '';
        for (let i = 0; i < bits.length; i += 5) {
          result += this.alphabet[parseInt(bits.substr(i, 5), 2)];
        }
        return result + '='.repeat((8 - (result.length % 8)) % 8);
      },
      decode: function(str) {
        if (!str) return '';
        str = str.replace(/=+$/, '').toUpperCase();
        let bits = '';
        for (let char of str) {
          const idx = this.alphabet.indexOf(char);
          if (idx === -1) throw new Error('Invalid Base32 character');
          bits += idx.toString(2).padStart(5, '0');
        }
        const bytes = [];
        for (let i = 0; i < bits.length; i += 8) {
          const byte = bits.substr(i, 8);
          if (byte.length === 8) bytes.push(parseInt(byte, 2));
        }
        return new TextDecoder().decode(new Uint8Array(bytes));
      }
    },
    base45: {
      alphabet: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:',
      encode: function(str) {
        if (!str) return '';
        const bytes = new TextEncoder().encode(str);
        let result = '';
        for (let i = 0; i < bytes.length; i += 2) {
          if (i + 1 < bytes.length) {
            const value = bytes[i] * 256 + bytes[i + 1];
            result += this.alphabet[Math.floor(value / (45 * 45)) % 45];
            result += this.alphabet[Math.floor(value / 45) % 45];
            result += this.alphabet[value % 45];
          } else {
            result += this.alphabet[bytes[i] % 45];
            if (bytes[i] >= 45) result += this.alphabet[Math.floor(bytes[i] / 45)];
          }
        }
        return result;
      },
      decode: function(str) {
        if (!str) return '';
        const bytes = [];
        for (let i = 0; i < str.length; i += 3) {
          if (i + 2 < str.length) {
            const v = this.alphabet.indexOf(str[i]) * 45 * 45 +
                     this.alphabet.indexOf(str[i + 1]) * 45 +
                     this.alphabet.indexOf(str[i + 2]);
            bytes.push(Math.floor(v / 256), v % 256);
          } else if (i + 1 < str.length) {
            const v = this.alphabet.indexOf(str[i]) * 45 + this.alphabet.indexOf(str[i + 1]);
            bytes.push(v);
          } else {
            bytes.push(this.alphabet.indexOf(str[i]));
          }
        }
        return new TextDecoder().decode(new Uint8Array(bytes));
      }
    },
    base58: {
      alphabet: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
      encode: function(str) {
        if (!str) return '';
        const bytes = new TextEncoder().encode(str);
        let num = BigInt(0);
        for (let byte of bytes) {
          num = num * 256n + BigInt(byte);
        }
        if (num === 0n) return '';
        let result = '';
        while (num > 0n) {
          result = this.alphabet[Number(num % 58n)] + result;
          num = num / 58n;
        }
        for (let byte of bytes) {
          if (byte === 0) result = '1' + result;
          else break;
        }
        return result;
      },
      decode: function(str) {
        if (!str) return '';
        let num = BigInt(0);
        for (let char of str) {
          const idx = this.alphabet.indexOf(char);
          if (idx === -1) throw new Error('Invalid Base58 character');
          num = num * 58n + BigInt(idx);
        }
        const bytes = [];
        while (num > 0n) {
          bytes.unshift(Number(num % 256n));
          num = num / 256n;
        }
        for (let char of str) {
          if (char === '1') bytes.unshift(0);
          else break;
        }
        return new TextDecoder().decode(new Uint8Array(bytes));
      }
    },
    base62: {
      alphabet: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
      encode: function(str) {
        if (!str) return '';
        const bytes = new TextEncoder().encode(str);
        let num = BigInt(0);
        for (let byte of bytes) {
          num = num * 256n + BigInt(byte);
        }
        if (num === 0n) return '0';
        let result = '';
        while (num > 0n) {
          result = this.alphabet[Number(num % 62n)] + result;
          num = num / 62n;
        }
        return result;
      },
      decode: function(str) {
        if (!str) return '';
        let num = BigInt(0);
        for (let char of str) {
          const idx = this.alphabet.indexOf(char);
          if (idx === -1) throw new Error('Invalid Base62 character');
          num = num * 62n + BigInt(idx);
        }
        const bytes = [];
        while (num > 0n) {
          bytes.unshift(Number(num % 256n));
          num = num / 256n;
        }
        return new TextDecoder().decode(new Uint8Array(bytes));
      }
    },
    base64: {
      encode: function(str) {
        if (!str) return '';
        return btoa(unescape(encodeURIComponent(str)));
      },
      decode: function(str) {
        if (!str) return '';
        try {
          return decodeURIComponent(escape(atob(str)));
        } catch (e) {
          throw new Error('Invalid Base64');
        }
      }
    },
    base85: {
      encode: function(str) {
        if (!str) return '';
        const bytes = new TextEncoder().encode(str);
        let result = '';
        for (let i = 0; i < bytes.length; i += 4) {
          let num = 0;
          const pad = Math.max(0, 4 - (bytes.length - i));
          for (let j = 0; j < 4 - pad; j++) {
            num = num * 256 + bytes[i + j];
          }
          if (num === 0 && pad === 0) {
            result += 'z';
            continue;
          }
          const digits = [];
          let temp = num;
          for (let j = 0; j < 5 - pad; j++) {
            digits.unshift(temp % 85);
            temp = Math.floor(temp / 85);
          }
          for (let digit of digits) {
            result += String.fromCharCode(33 + digit);
          }
        }
        return result;
      },
      decode: function(str) {
        if (!str) return '';
        const bytes = [];
        let i = 0;
        while (i < str.length) {
          if (str[i] === 'z') {
            bytes.push(0, 0, 0, 0);
            i++;
            continue;
          }
          let num = 0;
          let count = 0;
          while (i < str.length && count < 5) {
            const char = str[i];
            if (char === 'z') break;
            const val = char.charCodeAt(0) - 33;
            if (val < 0 || val >= 85) throw new Error('Invalid Base85 character');
            num = num * 85 + val;
            i++;
            count++;
          }
          const pad = 5 - count;
          for (let j = 0; j < 4 - pad; j++) {
            bytes.push((num >> (8 * (3 - j))) & 0xFF);
          }
        }
        return new TextDecoder().decode(new Uint8Array(bytes));
      }
    },
    base92: {
      alphabet: '!#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}',
      encode: function(str) {
        if (!str) return '';
        const bytes = new TextEncoder().encode(str);
        let num = BigInt(0);
        for (let byte of bytes) {
          num = num * 256n + BigInt(byte);
        }
        if (num === 0n) return '!';
        let result = '';
        while (num > 0n) {
          result = this.alphabet[Number(num % 92n)] + result;
          num = num / 92n;
        }
        return result;
      },
      decode: function(str) {
        if (!str) return '';
        let num = BigInt(0);
        for (let char of str) {
          const idx = this.alphabet.indexOf(char);
          if (idx === -1) throw new Error('Invalid Base92 character');
          num = num * 92n + BigInt(idx);
        }
        const bytes = [];
        while (num > 0n) {
          bytes.unshift(Number(num % 256n));
          num = num / 256n;
        }
        return new TextDecoder().decode(new Uint8Array(bytes));
      }
    }
  };

  function updateBase(editedField) {
    if (updating) return;
    updating = true;
    
    try {
      if (editedField === 'plaintext') {
        const value = basePlaintext.value;
        for (let [key, encoder] of Object.entries(baseEncoders)) {
          const input = document.getElementById('base-' + key);
          if (input) {
            try {
              input.value = encoder.encode(value);
            } catch (e) {
              input.value = '';
            }
          }
        }
      } else {
        const encoder = baseEncoders[editedField];
        const input = document.getElementById('base-' + editedField);
        if (encoder && input) {
          try {
            const plaintext = encoder.decode(input.value);
            basePlaintext.value = plaintext;
            for (let [key, enc] of Object.entries(baseEncoders)) {
              if (key !== editedField) {
                const otherInput = document.getElementById('base-' + key);
                if (otherInput) {
                  try {
                    otherInput.value = enc.encode(plaintext);
                  } catch (e) {
                    otherInput.value = '';
                  }
                }
              }
            }
          } catch (e) {
            basePlaintext.value = 'Error: ' + e.message;
          }
        }
      }
    } catch (e) {
      // Error
    }
    
    updating = false;
  }

  basePlaintext.addEventListener('input', () => updateBase('plaintext'));
  if (baseBase32) baseBase32.addEventListener('input', () => updateBase('base32'));
  if (baseBase45) baseBase45.addEventListener('input', () => updateBase('base45'));
  if (baseBase58) baseBase58.addEventListener('input', () => updateBase('base58'));
  if (baseBase62) baseBase62.addEventListener('input', () => updateBase('base62'));
  if (baseBase64) baseBase64.addEventListener('input', () => updateBase('base64'));
  if (baseBase85) baseBase85.addEventListener('input', () => updateBase('base85'));
  if (baseBase92) baseBase92.addEventListener('input', () => updateBase('base92'));
})();
