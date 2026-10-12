const LEASE_NAME_MAX_LENGTH = 63;
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
// The relay rejects names shaped like a canonical label: a 40-character hex
// address, alone or after a hyphen (utils.NormalizeServiceName).
const CANONICAL_SHAPE_PATTERN = /(^|-)[0-9a-f]{40}$/;

export function normalizeExposeName(value: string): string {
  const name = normalizeLabel(value);
  return CANONICAL_SHAPE_PATTERN.test(name) ? "" : name;
}

function normalizeLabel(value: string): string {
  const cleaned = sanitizeExposeNameInput(value);
  if (cleaned === "") {
    return "";
  }

  if (/^[a-z0-9-]+$/.test(cleaned)) {
    // Cutting punycode would corrupt it.
    if (cleaned.startsWith("xn--") && cleaned.length > LEASE_NAME_MAX_LENGTH) {
      return "";
    }
    return cleaned.slice(0, LEASE_NAME_MAX_LENGTH).replace(/-+$/, "");
  }

  // The URL parser maps some characters to ASCII punctuation, e.g. "⑴" to "(1)".
  const ascii = toASCIILabel(cleaned);
  if (ascii.length > LEASE_NAME_MAX_LENGTH || !DNS_LABEL_PATTERN.test(ascii)) {
    return "";
  }
  return ascii;
}

function sanitizeExposeNameInput(value: string): string {
  const input = value.trim().toLowerCase().normalize("NFC");
  if (input === "") {
    return "";
  }

  let output = "";
  let previousHyphen = false;

  for (const char of input) {
    if (char === "-" || /[\p{L}\p{N}]/u.test(char)) {
      output += char;
      previousHyphen = false;
      continue;
    }

    if (!previousHyphen) {
      output += "-";
      previousHyphen = true;
    }
  }

  return output.replace(/^-+|-+$/g, "");
}

function toASCIILabel(label: string): string {
  const suffix = ".example.test";

  try {
    const hostname = new URL(`https://${label}${suffix}`).hostname;
    if (!hostname.endsWith(suffix)) {
      return "";
    }
    return hostname.slice(0, -suffix.length);
  } catch {
    return "";
  }
}
