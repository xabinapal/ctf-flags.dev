export function mountUrl(panel) {
  const urlPlaintext = panel.querySelector("#url-plaintext");
  const urlEncoded = panel.querySelector("#url-encoded");

  if (!urlPlaintext || !urlEncoded) return;

  let updating = false;

  function updateURL(editedField) {
    if (updating) return;
    updating = true;

    try {
      if (editedField === "plaintext") {
        urlEncoded.value = encodeURIComponent(urlPlaintext.value);
      } else {
        try {
          urlPlaintext.value = decodeURIComponent(urlEncoded.value);
        } catch (e) {
          urlPlaintext.value = `Error: ${e.message}`;
        }
      }
    } catch {
      // Error handling
    }

    updating = false;
  }

  urlPlaintext.addEventListener("input", () => {
    if (!updating) updateURL("plaintext");
  });

  urlEncoded.addEventListener("input", () => {
    if (!updating) updateURL("encoded");
  });
}
