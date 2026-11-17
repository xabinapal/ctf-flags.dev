(() => {
  "use strict";

  const urlPlaintext = document.getElementById("url-plaintext");
  const urlEncoded = document.getElementById("url-encoded");

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
})();
