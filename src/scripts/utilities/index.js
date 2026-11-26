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
const buttons = utilities.querySelectorAll("button[data-utility]");
const panels = utilities.querySelectorAll("[data-utility-panel]");

for (const panel of panels) mount[panel.dataset.utilityPanel](panel);

for (const button of buttons) {
  button.addEventListener("click", () => {
    for (const option of buttons) {
      const selected = option === button;
      option.classList.toggle("active", selected);
      option.setAttribute("aria-pressed", String(selected));
    }
    for (const panel of panels) {
      panel.hidden = panel.id !== button.getAttribute("aria-controls");
    }
  });
}

utilities.inert = false;
