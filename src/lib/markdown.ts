import { unified } from "@astrojs/markdown-remark";
import { type DefaultTreeAdapterTypes, parseFragment } from "parse5";

type Node = DefaultTreeAdapterTypes.Node;

let renderer:
  | ReturnType<ReturnType<typeof unified>["createRenderer"]>
  | undefined;

export async function renderSummary(markdown = "") {
  renderer ??= unified().createRenderer({ syntaxHighlight: false });
  return (await (await renderer).render(markdown)).code;
}

export function truncateWords(text: string, limit = 160) {
  const words = text.trim().split(/\s+/u);
  const result: string[] = [];
  let length = 0;
  for (const [index, word] of words.entries()) {
    length += (index === 0 ? 0 : 1) + [...word].length;
    if (length > limit && index < words.length - 1)
      return `${result.join(" ")}...`;
    result.push(word);
  }
  return result.join(" ");
}

const blockTags = new Set([
  "article",
  "blockquote",
  "br",
  "div",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "hr",
  "li",
  "ol",
  "p",
  "pre",
  "section",
  "table",
  "td",
  "th",
  "tr",
  "ul",
]);

function textContent(node: Node): string {
  if ("value" in node) return node.value;
  if (!("childNodes" in node)) return "";
  const text = node.childNodes.map(textContent).join("");
  return "tagName" in node && blockTags.has(node.tagName) ? ` ${text} ` : text;
}

export function plainText(html: string) {
  return textContent(parseFragment(html)).replace(/\s+/gu, " ").trim();
}

export function writeupDescription(html: string) {
  const content = parseFragment(html).childNodes;
  const heading = content.findIndex(
    (node) => "tagName" in node && node.tagName === "h2",
  );
  if (heading === -1) return "";

  const paragraph = content
    .slice(heading + 1)
    .find((node) => "tagName" in node && node.tagName === "p");
  return paragraph ? truncateWords(textContent(paragraph)) : "";
}
