type Consent = "granted" | "denied";
type StorageName = "localStorage" | "sessionStorage";

declare global {
  interface Window {
    dataLayer?: unknown[];
  }
}

const consentKey = "cookieConsent";
const measurementId = "G-Z41SBL7P3W";

function readConsent(storage: StorageName): Consent | undefined {
  try {
    const value = window[storage].getItem(consentKey);
    if (value === "granted" || value === "denied") return value;
  } catch {
    // The browser may deny access to storage for this page.
  }
  return undefined;
}

function saveConsent(storage: StorageName, consent: Consent) {
  try {
    window[storage].setItem(consentKey, consent);
    return true;
  } catch {
    return false;
  }
}

function startAnalytics() {
  window.dataLayer ??= [];
  const dataLayer = window.dataLayer;
  function gtag(..._args: unknown[]) {
    // biome-ignore lint/complexity/noArguments: Use Google's arguments-based command queue.
    dataLayer.push(arguments);
  }

  const settings = (consent: Consent) => ({
    ad_storage: consent,
    analytics_storage: consent,
    ad_user_data: consent,
    ad_personalization: consent,
  });
  gtag("consent", "default", settings("denied"));
  gtag("consent", "update", settings("granted"));
  gtag("js", new Date());
  gtag("config", measurementId);

  const script = document.createElement("script");
  script.async = true;
  script.src = `https://www.googletagmanager.com/gtag/js?id=${measurementId}`;
  document.head.append(script);
}

const banner = document.getElementById("cookie-consent-banner");
if (banner) {
  const savedConsent =
    readConsent("sessionStorage") ?? readConsent("localStorage");
  if (savedConsent === "granted") startAnalytics();

  if (!savedConsent) {
    banner.hidden = false;

    const choose = (choice: Consent) => {
      if (banner.hidden) return;
      banner.hidden = true;
      if (choice === "granted") {
        if (!saveConsent("localStorage", choice))
          saveConsent("sessionStorage", choice);
        startAnalytics();
      } else {
        saveConsent("sessionStorage", choice);
      }
    };

    banner
      .querySelector("#consent-accept")
      ?.addEventListener("click", () => choose("granted"));
    banner
      .querySelector("#consent-decline")
      ?.addEventListener("click", () => choose("denied"));
  }
}

export {};
