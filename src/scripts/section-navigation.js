import { fullPageTitle } from "../lib/site";

export function sectionPathname() {
  const { pathname } = location;
  return pathname.endsWith("/") ? pathname : `${pathname}/`;
}

/** @param {string} pathname */
export function navigateSection(pathname) {
  const url = new URL(location.href);
  url.pathname = pathname;
  if (url.href !== location.href) history.pushState(history.state, "", url);
}

/** @param {string} path @param {{ title: string; description: string }} metadata */
export function updateSectionMetadata(path, { title, description }) {
  const canonical = document.querySelector('link[rel="canonical"]');
  if (!(canonical instanceof HTMLLinkElement)) return;
  const url = new URL(path, canonical.href).href;
  canonical.href = url;
  document.title = fullPageTitle(title);

  for (const [selector, value] of [
    [
      'meta[name="description"], meta[property="og:description"], meta[name="twitter:description"]',
      description,
    ],
    ['meta[property="og:title"], meta[name="twitter:title"]', document.title],
    ['meta[property="og:url"], meta[name="twitter:url"]', url],
  ]) {
    for (const meta of document.head.querySelectorAll(selector))
      meta.setAttribute("content", value);
  }
}
