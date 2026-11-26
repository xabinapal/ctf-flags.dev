import { fieldError } from "./fields.js";

const flags = [
  "flag{nice_try}",
  "flag{follow_the_bytes}",
  "flag{gremlins_were_here}",
  "flag{look_closer}",
  "flag{bit_by_bit}",
  "flag{zero_day_off}",
  "flag{one_more_hexdump}",
  "flag{the_cake_is_base64}",
  "flag{mind_the_null_byte}",
  "flag{read_the_packet}",
  "flag{entropy_is_a_clue}",
  "flag{not_that_kind_of_shell}",
  "flag{some_assembly_required}",
  "flag{first_try_allegedly}",
  "flag{a_haystack_of_needles}",
  "flag{the_bits_are_talking}",
  "flag{the_checksum_checks_out}",
  "flag{be_kind_to_the_stack}",
  "flag{printf_debugging_forever}",
  "flag{lost_in_little_endian}",
  "flag{reverse_the_reverse}",
  "flag{warm_up_is_a_lie}",
  "flag{you_had_me_at_magic_bytes}",
  "flag{one_bit_off}",
  "flag{rotate_responsibly}",
  "flag{the_flag_was_a_decoy}",
  "flag{spot_the_odd_byte}",
  "flag{regex_went_for_coffee}",
  "flag{cache_me_if_you_can}",
  "flag{a_very_normal_png}",
  "flag{nothing_to_spectrogram_here}",
  "flag{open_the_other_attachment}",
  "flag{we_found_it_in_the_footer}",
  "flag{byte_me}",
  "flag{no_sleep_till_submit}",
  "flag{this_took_five_minutes_ish}",
  "flag{put_it_in_the_writeup}",
  "flag{the_repl_remembers}",
  "flag{have_you_tried_hex}",
  "flag{a_flag_in_every_port}",
  "flag{never_trust_the_extension}",
  "flag{down_the_rabbit_hole}",
  "flag{ye_olde_ascii_table}",
  "flag{look_mum_no_spaces}",
  "flag{a_byte_of_fresh_air}",
  "flag{blame_the_clock}",
  "flag{the_padding_was_a_clue}",
  "flag{count_the_braces}",
  "flag{side_quest_complete}",
  "flag{the_cat_read_the_docs}",
  "flag{same_bytes_different_hat}",
  "flag{the_plot_thickens_at_offset_zero}",
  "flag{time_is_a_flat_timestamp}",
  "flag{it_was_unicode_all_along}",
  "flag{someone_moved_the_goalposts}",
  "flag{flags_within_flags}",
  "flag{the_phantom_newline}",
  "flag{garbage_in_flag_out}",
  "flag{the_last_draft_was_final}",
  "flag{all_your_base_are_hex}",
  "flag{it_compiled_on_the_first_try}",
  "flag{the_console_knows}",
  "flag{seven_bits_of_trouble}",
  "flag{just_one_more_tab}",
];

let remaining = [];
let lastFlag;

function nextFlag() {
  const refilling = remaining.length === 0;
  if (refilling) remaining = flags.filter((flag) => flag !== lastFlag);
  const index = Math.floor(Math.random() * remaining.length);
  const [flag] = remaining.splice(index, 1);
  if (refilling && lastFlag) remaining.push(lastFlag);
  lastFlag = flag;
  return flag;
}

const examples = {
  number: (pickFlag) => ({ "num-ascii": pickFlag() }),
  base: (pickFlag) => ({ "base-plaintext": pickFlag() }),
  url: (pickFlag) => ({ "url-plaintext": pickFlag() }),
  rot: (pickFlag) => ({ "rot-plaintext": pickFlag() }),
  xor: (pickFlag) => ({ "xor-input-ascii": pickFlag(), "xor-key-hex": "01" }),
  morse: (pickFlag) => ({
    "morse-plaintext": pickFlag().replace("{", "(").replace("}", ")"),
  }),
  timestamp: () => ({ "ts-iso8601": "2026-01-01T00:00:00Z" }),
  jwt: (pickFlag) => ({
    "jwt-header": '{"typ":"JWT","alg":"HS256"}',
    "jwt-payload": JSON.stringify({ flag: pickFlag() }, null, 2),
  }),
};

export function mountActions(panel) {
  const toolbarClear = panel.querySelector("[data-clear]");
  const toolbarExample = panel.querySelector("[data-example]");
  const status = panel.querySelector("[data-copy-status]");
  const fields = [...panel.querySelectorAll("input, textarea")];
  const copies = [...panel.querySelectorAll("[data-copy]")].map((button) => ({
    button,
    field: panel.querySelector(`#${button.dataset.copy}`),
  }));

  function refresh() {
    toolbarClear.disabled = !fields.some(
      (field) =>
        field.value !== field.defaultValue ||
        field.hasAttribute("aria-invalid"),
    );
    for (const { button, field } of copies) {
      button.disabled = !field.value;
      button.textContent = "Copy";
    }
  }

  function reset() {
    for (const field of fields) {
      field.value = field.defaultValue;
      fieldError(field);
    }
    status.textContent = "";
    refresh();
  }

  panel.addEventListener("input", () => {
    status.textContent = "";
    refresh();
  });
  toolbarClear.addEventListener("click", () => {
    reset();
    fields[0]?.focus();
  });
  toolbarExample.addEventListener("click", () => {
    reset();
    for (const [id, sample] of Object.entries(
      examples[panel.dataset.utilityPanel](nextFlag),
    )) {
      const field = panel.querySelector(`#${id}`);
      field.value = sample;
      field.dispatchEvent(new Event("input", { bubbles: true }));
    }
  });
  for (const { button, field } of copies) {
    button.addEventListener("click", async () => {
      for (const copy of copies) copy.button.textContent = "Copy";
      try {
        await navigator.clipboard.writeText(field.value);
        button.textContent = "Copied";
        status.textContent = `${button.getAttribute("aria-label").replace(/^Copy /u, "")} copied.`;
      } catch {
        field.focus();
        field.select();
        button.textContent = "Selected";
        status.textContent =
          "Clipboard access was blocked. The value is selected for manual copying.";
      }
    });
  }
  refresh();
}
