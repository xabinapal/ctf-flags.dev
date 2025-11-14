(function() {
  const searchInput = document.getElementById('resource-search');
  const categoryFilters = document.querySelectorAll('.chip-rounded[data-category]');
  const resourceItems = document.querySelectorAll('.list-item');
  const resourceCategories = document.querySelectorAll('.category');
  const noResults = document.getElementById('no-results');
  const resourcesContainer = document.getElementById('resources-container');

  let currentCategory = 'all';
  let currentSearch = '';

  function filterResources() {
    let visibleCount = 0;
    let visibleCategories = new Set();

    resourceItems.forEach(item => {
      const name = item.dataset.name || '';
      const description = item.dataset.description || '';
      const category = item.dataset.category || '';
      
      const matchesSearch = currentSearch === '' || 
        name.includes(currentSearch.toLowerCase()) || 
        description.includes(currentSearch.toLowerCase());
      
      const matchesCategory = currentCategory === 'all' || category === currentCategory;

      if (matchesSearch && matchesCategory) {
        item.style.display = '';
        visibleCategories.add(category);
        visibleCount++;
      } else {
        item.style.display = 'none';
      }
    });

    // Show/hide category sections
    resourceCategories.forEach(categoryEl => {
      const categorySlug = categoryEl.dataset.category;
      const hasVisibleItems = Array.from(categoryEl.querySelectorAll('.list-item')).some(
        item => item.style.display !== 'none'
      );
      
      if (hasVisibleItems) {
        categoryEl.style.display = '';
      } else {
        categoryEl.style.display = 'none';
      }
    });

    // Show/hide no results message
    if (visibleCount === 0) {
      noResults.style.display = 'block';
      resourcesContainer.style.display = 'none';
    } else {
      noResults.style.display = 'none';
      resourcesContainer.style.display = '';
    }
  }

  // Search input handler
  searchInput.addEventListener('input', function(e) {
    currentSearch = e.target.value.trim();
    filterResources();
  });

  // Category filter handlers
  categoryFilters.forEach(filter => {
    filter.addEventListener('click', function() {
      categoryFilters.forEach(f => f.classList.remove('active'));
      this.classList.add('active');
      currentCategory = this.dataset.category;
      filterResources();
    });
  });

  // Initial filter
  filterResources();
})();

