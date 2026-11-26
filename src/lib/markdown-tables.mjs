/** @type {import("@astrojs/markdown-remark").RehypePlugin} */
export function scrollableMarkdownTables() {
  return (tree) => {
    function wrapTables(parent) {
      for (const [index, child] of parent.children.entries()) {
        if (child.type !== "element") continue;

        wrapTables(child);
        if (child.tagName === "table") {
          parent.children[index] = {
            type: "element",
            tagName: "div",
            properties: {
              className: ["markdown-table-scroll"],
              role: "region",
              ariaLabel: "Scrollable table",
              tabIndex: 0,
            },
            children: [child],
          };
        }
      }
    }

    wrapTables(tree);
  };
}
