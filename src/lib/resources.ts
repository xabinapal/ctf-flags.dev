export function resourcePath(category?: string) {
  return category ? `/resources/${category}/` : "/resources/";
}
