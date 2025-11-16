// Shared utilities for all utility scripts
window.UtilityShared = (function() {
  'use strict';
  
  // Track which input is being edited to prevent circular updates
  const activeInputs = new Set();
  
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
  
  return {
    activeInputs: activeInputs,
    escapeHtml: escapeHtml
  };
})();

