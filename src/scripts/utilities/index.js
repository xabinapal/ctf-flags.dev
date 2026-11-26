import { utilityMetadata, utilityPath } from "../../lib/utilities";
import {
  navigateSection,
  sectionPathname,
  updateSectionMetadata,
} from "../section-navigation.js";
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
    const path = sectionPathname();
    const matched = buttons.find((button) => button.dataset.path === path);
    const selected = matched ?? buttons[0];
    updateSectionMetadata(
      matched?.dataset.path ?? utilityPath(),
      utilityMetadata(matched?.dataset.utility),
    );

    for (const button of buttons) {
      const active = button === selected;
      button.setAttribute("aria-pressed", String(active));
    }
    for (const panel of panels) {
      panel.hidden = panel.id !== selected.getAttribute("aria-controls");
    }
  }

  for (const button of buttons) {
    button.addEventListener("click", () => {
      navigateSection(button.dataset.path);
      restore();
    });
  }
  window.addEventListener("popstate", restore);
  restore();
  utilities.inert = false;
}
