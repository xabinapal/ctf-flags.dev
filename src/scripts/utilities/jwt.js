import { errorMessage, fieldError, utilityField } from "./fields.js";

const decoder = new TextDecoder("utf-8", { fatal: true });
const encoder = new TextEncoder();
const base64Url = /^[\w-]*$/u;

function jsonObject(text) {
  const value = JSON.parse(text);
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error();
}

function decodeJson(segment, name) {
  try {
    const decoded = atob(segment.replace(/-/gu, "+").replace(/_/gu, "/"));
    const bytes = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
    const text = decoder.decode(bytes);
    jsonObject(text);
    return text;
  } catch {
    throw new Error(
      `The JWT ${name} must contain a Base64URL-encoded JSON object.`,
    );
  }
}

function encodeJson(text) {
  jsonObject(text);
  const bytes = Array.from(encoder.encode(text.trim()), (byte) =>
    String.fromCharCode(byte),
  ).join("");
  return btoa(bytes)
    .replace(/\+/gu, "-")
    .replace(/\//gu, "_")
    .replace(/=+$/u, "");
}

export function mountJwt(panel) {
  const token = utilityField(panel, "jwt-input");
  const header = utilityField(panel, "jwt-header");
  const payload = utilityField(panel, "jwt-payload");
  const signature = utilityField(panel, "jwt-signature");
  const parts = [header, payload, signature];

  token.addEventListener("input", () => {
    fieldError(token);
    for (const part of parts) {
      part.value = "";
      fieldError(part);
    }
    const value = token.value.trim();
    if (!value) return;
    try {
      const [encodedHeader, encodedPayload, encodedSignature, extra] =
        value.split(".");
      if (
        !encodedHeader ||
        !encodedPayload ||
        encodedSignature === undefined ||
        extra !== undefined ||
        ![encodedHeader, encodedPayload, encodedSignature].every((part) =>
          base64Url.test(part),
        )
      ) {
        throw new Error("Enter three Base64URL segments separated by dots.");
      }
      const decodedHeader = decodeJson(encodedHeader, "header");
      const decodedPayload = decodeJson(encodedPayload, "payload");
      header.value = decodedHeader;
      payload.value = decodedPayload;
      signature.value = encodedSignature;
    } catch (error) {
      fieldError(token, errorMessage(error));
    }
  });

  function rebuildToken() {
    fieldError(token);
    token.value = "";
    const segments = [header, payload].map((field) => {
      fieldError(field);
      if (!field.value.trim()) return null;
      try {
        return encodeJson(field.value);
      } catch {
        fieldError(field, "Enter a valid JSON object.");
        return null;
      }
    });
    const validSignature = base64Url.test(signature.value);
    fieldError(
      signature,
      validSignature ? "" : "Use Base64URL characters without padding.",
    );
    if (validSignature && segments.every(Boolean)) {
      token.value = [...segments, signature.value].join(".");
    }
  }

  for (const part of parts) part.addEventListener("input", rebuildToken);
}
