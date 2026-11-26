export function resourcePath(category?: string) {
  return category ? `/resources/${category}/` : "/resources/";
}

export function resourceMetadata(category?: string) {
  const label = category?.toUpperCase();
  return {
    title: label ? `${label} resources` : "Resources",
    description: label
      ? `Browse ${label} tools and references for capture-the-flag challenges.`
      : "Tools and references organized by CTF category.",
  };
}
