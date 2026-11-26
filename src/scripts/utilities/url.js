import { mountConversions } from "./fields.js";

export function mountUrl(panel) {
  mountConversions(panel, {
    "url-plaintext": { decode: (value) => value, encode: (value) => value },
    "url-encoded": {
      encode: encodeURIComponent,
      decode(value) {
        try {
          return decodeURIComponent(value);
        } catch {
          throw new Error(
            "Use valid percent escapes containing UTF-8 bytes, such as %20.",
          );
        }
      },
    },
  });
}
