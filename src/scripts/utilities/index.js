import { mountBase } from "./base.js";
import { mountJwt } from "./jwt.js";
import { mountMorse } from "./morse.js";
import { mountNumber } from "./number.js";
import { mountRot } from "./rot.js";
import { mountTimestamp } from "./timestamp.js";
import { mountUrl } from "./url.js";
import { mountXor } from "./xor.js";

const mount = {
  base: mountBase,
  jwt: mountJwt,
  morse: mountMorse,
  number: mountNumber,
  rot: mountRot,
  timestamp: mountTimestamp,
  url: mountUrl,
  xor: mountXor,
};
const utilities = document.querySelector("[data-utilities]");
if (utilities) {
  const buttons = [...utilities.querySelectorAll("button[data-utility]")];
  const panels = utilities.querySelectorAll("[data-utility-panel]");

  for (const panel of panels) mount[panel.dataset.utilityPanel](panel);

  function restore() {
    const path = location.pathname.endsWith("/")
      ? location.pathname
      : `${location.pathname}/`;
    const selected =
      buttons.find((button) => button.dataset.path === path) ?? buttons[0];

    for (const button of buttons) {
      const active = button === selected;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    }
    for (const panel of panels) {
      panel.hidden = panel.id !== selected.getAttribute("aria-controls");
    }
  }

  for (const button of buttons) {
    button.addEventListener("click", () => {
      const url = new URL(location.href);
      url.pathname = button.dataset.path;
      if (url.href !== location.href) history.pushState(history.state, "", url);
      restore();
    });
  }
  window.addEventListener("popstate", restore);
  restore();
  utilities.inert = false;
}
