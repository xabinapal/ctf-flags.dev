export const siteTitle = "ctf-flags.dev";

export function fullPageTitle(title?: string) {
  return title ? `${title} | ${siteTitle}` : siteTitle;
}
