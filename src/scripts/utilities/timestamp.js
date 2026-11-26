import { mountConversions } from "./fields.js";

const nanosecondsPerMillisecond = 1_000_000n;
const nanosecondsPerSecond = 1_000_000_000n;
const filetimeOffset = 11_644_473_600n * nanosecondsPerSecond;
const limit = 8_640_000_000_000_000n * nanosecondsPerMillisecond;

function integer(value) {
  if (!/^[+-]?(?:\d+|0x[\da-f]+)$/iu.test(value)) {
    throw new Error("Enter a whole number in decimal or with a 0x prefix.");
  }
  const magnitude = BigInt(value.replace(/^[+-]/u, ""));
  return value.startsWith("-") ? -magnitude : magnitude;
}

function checked(value) {
  if (value < -limit || value > limit)
    throw new Error("Timestamp is outside the supported date range.");
  return value;
}

function numericFormat(unit, offset = 0n) {
  return {
    normalize: (value) => value.trim(),
    decode: (value) => checked(integer(value) * unit - offset),
    encode(value) {
      const adjusted = value + offset;
      const quotient = adjusted / unit;
      return (adjusted % unit < 0n ? quotient - 1n : quotient).toString();
    },
  };
}

function fromIso(value) {
  const match =
    /^([+-]\d{6}|\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2})?)?$/iu.exec(
      value,
    );
  if (!match)
    throw new Error("Enter an ISO 8601 date, such as 2026-01-01T00:00:00Z.");
  const [
    ,
    year,
    month,
    day,
    hour = "00",
    minute = "00",
    second = "00",
    fraction = "",
    zone = "Z",
  ] = match;
  const local = `${year}-${month}-${day}T${hour}:${minute}:${second}`;
  const utc = new Date(`${local}Z`);
  const ms = Date.parse(local + zone.toUpperCase());
  if (
    !Number.isFinite(ms) ||
    !Number.isFinite(utc.getTime()) ||
    utc.toISOString().slice(0, -5) !== local
  ) {
    throw new Error("Enter a valid calendar date and time.");
  }
  return checked(
    BigInt(ms) * nanosecondsPerMillisecond + BigInt(fraction.padEnd(9, "0")),
  );
}

function toIso(value) {
  const fraction =
    ((value % nanosecondsPerSecond) + nanosecondsPerSecond) %
    nanosecondsPerSecond;
  const seconds = (value - fraction) / nanosecondsPerMillisecond;
  const date = new Date(Number(seconds)).toISOString();
  return `${date.slice(0, -5)}.${fraction.toString().padStart(9, "0").replace(/0+$/u, "").padEnd(3, "0")}Z`;
}

export function mountTimestamp(panel) {
  mountConversions(panel, {
    "ts-unix-seconds": numericFormat(nanosecondsPerSecond),
    "ts-unix-milliseconds": numericFormat(nanosecondsPerMillisecond),
    "ts-unix-nanoseconds": numericFormat(1n),
    "ts-windows": numericFormat(100n, filetimeOffset),
    "ts-iso8601": {
      normalize: (value) => value.trim(),
      decode: fromIso,
      encode: toIso,
    },
  });
}
