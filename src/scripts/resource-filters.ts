import {
  navigateSection,
  sectionPathname,
  updateSectionMetadata,
} from "./section-navigation.js";
import { resourceMetadata, resourcePath } from "../lib/resources";

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
  let category = "";
  let editingSearch = false;

  function render(query: string, emptyMessage: HTMLElement) {
    const normalizedQuery = query.trim().toLowerCase();
    let hasResults = false;

    for (const { element, items } of categories) {
      const matchesCategory =
        !category || element.dataset.category === category;
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
      const active = button.dataset.category === category;
      button.setAttribute("aria-pressed", String(active));
    }
  }

  const restore = () => {
    const url = new URL(location.href);
    const path = sectionPathname();
    category =
      buttons.find((button) => resourcePath(button.dataset.category) === path)
        ?.dataset.category ?? "";
    updateSectionMetadata(resourcePath(category), resourceMetadata(category));
    search.value = url.searchParams.get("q") ?? "";
    editingSearch = false;
    render(search.value, noResults);
  };

  search.addEventListener("input", () => {
    const url = new URL(location.href);
    const query = search.value.trim();
    if (query) url.searchParams.set("q", query);
    else url.searchParams.delete("q");

    // Keep one Back step per search edit rather than one per keystroke.
    if (url.href !== location.href) {
      if (editingSearch) history.replaceState(history.state, "", url);
      else history.pushState(history.state, "", url);
      editingSearch = true;
    }
    render(search.value, noResults);
  });
  search.addEventListener("blur", () => {
    editingSearch = false;
  });
  for (const button of buttons) {
    button.addEventListener("click", () => {
      category = button.dataset.category ?? "";
      editingSearch = false;

      const path = resourcePath(category);
      navigateSection(path);
      updateSectionMetadata(path, resourceMetadata(category));
      render(search.value, noResults);
    });
  }
  window.addEventListener("popstate", restore);
  restore();
  controls.inert = false;
}
