export function utilityField(panel, id) {
  return panel.querySelector(`#${id}`);
}

export function fieldMessage(field, message = "") {
  const hint = document.getElementById(`${field.id}-message`);
  if (hint) hint.textContent = message;
}

export function fieldError(field, message = "") {
  if (message) field.setAttribute("aria-invalid", "true");
  else field.removeAttribute("aria-invalid");
  fieldMessage(field, message);
}

export function errorMessage(error) {
  return error instanceof Error ? error.message : "Conversion failed.";
}

/** Synchronize editable representations without replacing the active input. */
export function mountConversions(panel, formats) {
  const fields = Object.entries(formats).map(([id, format]) => ({
    field: utilityField(panel, id),
    ...format,
  }));
  let active = fields[0];

  function update(preferredId) {
    if (preferredId)
      active = fields.find(({ field }) => field.id === preferredId) ?? active;
    for (const { field } of fields) fieldError(field);
    try {
      const value = (active.normalize ?? ((value) => value))(
        active.field.value,
      );
      const decoded = value === "" ? null : active.decode(value);
      const outputs = fields.map((format) =>
        format === active || decoded === null ? "" : format.encode(decoded),
      );
      fields.forEach((format, index) => {
        if (format !== active) format.field.value = outputs[index];
      });
    } catch (error) {
      for (const { field } of fields) {
        if (field !== active.field) field.value = "";
      }
      fieldError(active.field, errorMessage(error));
    }
  }

  for (const format of fields) {
    format.field.addEventListener("input", () => {
      active = format;
      update();
    });
  }
  return update;
}
