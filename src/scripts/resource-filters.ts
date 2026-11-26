const controls = document.querySelector<HTMLElement>(
  "[data-resource-controls]",
);
const search = document.querySelector<HTMLInputElement>("#resource-search");
const noResults = document.querySelector<HTMLElement>("#no-results");
const buttons = [
  ...document.querySelectorAll<HTMLButtonElement>(
    "[data-resource-controls] button[data-category]",
  ),
];
const categories = [
  ...document.querySelectorAll<HTMLElement>("#resources-container .category"),
].map((element) => ({
  element,
  items: [...element.querySelectorAll<HTMLElement>(".list-item")],
}));

if (controls && search && noResults) {
  let category = "all";
  let editingSearch = false;

  function render(
    query: string,
    activeCategory: string,
    emptyMessage: HTMLElement,
  ) {
    const normalizedQuery = query.trim().toLowerCase();
    let hasResults = false;

    for (const { element, items } of categories) {
      const matchesCategory =
        activeCategory === "all" || element.dataset.category === activeCategory;
      for (const item of items) {
        const matchesQuery =
          (item.dataset.name ?? "").includes(normalizedQuery) ||
          (item.dataset.description ?? "").includes(normalizedQuery);
        item.hidden = !matchesCategory || !matchesQuery;
      }
      element.hidden = items.every((item) => item.hidden);
      hasResults ||= !element.hidden;
    }
    emptyMessage.hidden = hasResults;

    for (const button of buttons) {
      const active = button.dataset.category === activeCategory;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    }
  }

  function updateUrl(
    query: string,
    activeCategory: string,
    action: "pushState" | "replaceState",
  ) {
    const url = new URL(location.href);
    const value = query.trim();
    if (value) url.searchParams.set("q", value);
    else url.searchParams.delete("q");

    if (activeCategory !== "all")
      url.searchParams.set("category", activeCategory);
    else url.searchParams.delete("category");

    if (url.href === location.href) return false;
    history[action](history.state, "", url);
    return true;
  }

  const restore = () => {
    const { searchParams } = new URL(location.href);
    const requestedCategory = searchParams.get("category");
    category = buttons.some(
      (button) => button.dataset.category === requestedCategory,
    )
      ? (requestedCategory ?? "all")
      : "all";
    search.value = searchParams.get("q") ?? "";
    editingSearch = false;
    render(search.value, category, noResults);
  };

  search.addEventListener("input", () => {
    // Keep one Back step per search edit rather than one per keystroke.
    const changed = updateUrl(
      search.value,
      category,
      editingSearch ? "replaceState" : "pushState",
    );
    editingSearch ||= changed;
    render(search.value, category, noResults);
  });
  search.addEventListener("blur", () => {
    editingSearch = false;
  });
  for (const button of buttons) {
    button.addEventListener("click", () => {
      category = button.dataset.category ?? "all";
      editingSearch = false;
      updateUrl(search.value, category, "pushState");
      render(search.value, category, noResults);
    });
  }
  window.addEventListener("popstate", restore);
  restore();
  controls.inert = false;
}
