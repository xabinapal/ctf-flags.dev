(function() {
  'use strict';
  
  const utilityContainer = document.getElementById('utility-container');
  const utilityChips = document.querySelectorAll('.utility-chip');
  let currentUtility = null;
  
  const utilityMap = {
    'number': 'number',
    'base': 'base',
    'url': 'url',
    'timestamp': 'timestamp',
    'morse': 'morse',
    'rot': 'rot',
    'xor': 'xor',
    'jwt': 'jwt'
  };
  
  function executeScripts(container) {
    // Find and execute all script tags in the loaded HTML
    const scripts = container.querySelectorAll('script');
    scripts.forEach(oldScript => {
      const newScript = document.createElement('script');
      
      // Copy attributes
      Array.from(oldScript.attributes).forEach(attr => {
        newScript.setAttribute(attr.name, attr.value);
      });
      
      // Copy inline script content
      if (oldScript.innerHTML) {
        newScript.innerHTML = oldScript.innerHTML;
      }
      
      // Replace old script with new one (this will execute it)
      oldScript.parentNode.replaceChild(newScript, oldScript);
    });
  }
  
  function unloadUtility() {
    if (utilityContainer) {
      utilityContainer.innerHTML = '';
    }
    currentUtility = null;
  }
  
  function loadUtility(name) {
    if (currentUtility === name) return;
    
    unloadUtility();
    
    const pageName = utilityMap[name];
    if (!pageName) return;
    
    // Get base path from the loader script itself
    const loaderScript = document.querySelector('script[src*="loader.js"]');
    let basePath = '';
    if (loaderScript) {
      const loaderSrc = loaderScript.src;
      const assetsIndex = loaderSrc.indexOf('/assets/');
      if (assetsIndex !== -1) {
        basePath = loaderSrc.substring(0, assetsIndex);
      }
    }
    
    // Fetch the HTML from the utility page
    const pagePath = basePath + '/partials/utilities/' + pageName + '.html';
    
    fetch(pagePath)
      .then(response => {
        if (!response.ok) throw new Error('Failed to load utility');
        return response.text();
      })
      .then(html => {
        if (utilityContainer) {
          utilityContainer.innerHTML = html;
          // Execute any script tags in the loaded HTML
          executeScripts(utilityContainer);
        }
        
        currentUtility = name;
        
        // Update active chip
        utilityChips.forEach(chip => {
          if (chip.dataset.utility === name) {
            chip.classList.add('active');
          } else {
            chip.classList.remove('active');
          }
        });
      })
      .catch(error => {
        console.error('Error loading utility:', error);
        if (utilityContainer) {
          utilityContainer.innerHTML = '<div class="error">Error loading utility: ' + error.message + '</div>';
        }
      });
  }
  
  // Initialize with first utility
  if (utilityChips.length > 0) {
    const firstChip = document.querySelector('.utility-chip.active');
    if (firstChip) {
      loadUtility(firstChip.dataset.utility);
    } else {
      loadUtility(utilityChips[0].dataset.utility);
    }
  }
  
  // Add click handlers
  utilityChips.forEach(chip => {
    chip.addEventListener('click', function() {
      loadUtility(this.dataset.utility);
    });
  });
})();
