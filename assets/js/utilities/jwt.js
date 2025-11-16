(function() {
  'use strict';
  
  const jwtInput = document.getElementById('jwt-input');
  const jwtHeader = document.getElementById('jwt-header');
  const jwtPayload = document.getElementById('jwt-payload');
  const jwtSignature = document.getElementById('jwt-signature');
  
  if (!jwtInput) return;

  function parseJWT(token) {
    if (!token.trim()) {
      if (jwtHeader) jwtHeader.textContent = '';
      if (jwtPayload) jwtPayload.textContent = '';
      if (jwtSignature) jwtSignature.textContent = '';
      return;
    }
    try {
      const parts = token.trim().split('.');
      if (parts.length !== 3) throw new Error('Invalid JWT format');
      
      const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      const signature = parts[2];
      
      if (jwtHeader) jwtHeader.textContent = JSON.stringify(header, null, 2);
      if (jwtPayload) jwtPayload.textContent = JSON.stringify(payload, null, 2);
      if (jwtSignature) jwtSignature.textContent = signature;
    } catch (e) {
      if (jwtHeader) jwtHeader.textContent = 'Error: ' + e.message;
      if (jwtPayload) jwtPayload.textContent = '';
      if (jwtSignature) jwtSignature.textContent = '';
    }
  }

  jwtInput.addEventListener('input', function() {
    parseJWT(jwtInput.value);
  });
})();
