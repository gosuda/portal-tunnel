const DEFAULT_TARGET_PORT = "3000";
const DEFAULT_TARGET_HOST = "127.0.0.1";

const exposeNameOpeners = [
  "arcade", "bouncy", "bravo", "bubble", "candy", "cosmic", "dapper", "electric",
  "fancy", "fizzy", "flashy", "fuzzy", "gentle", "glitter", "golden", "happy",
  "hyper", "jazzy", "jolly", "lively", "lucky", "magic", "mellow", "minty",
  "misty", "moonlit", "mystic", "neon", "nova", "peppy", "pixel", "playful",
  "poppy", "rapid", "rocket", "rowdy", "snappy", "snazzy", "sparkly", "spicy",
  "sprightly", "starry", "sunny", "swift", "tangy", "tidy", "toasty", "turbo",
  "velvet", "vivid", "wavy", "whimsy", "wild", "wonky", "zany", "zesty",
] as const;

const exposeNameCenters = [
  "alpaca", "badger", "banjo", "beacon", "biscuit", "capybara", "comet", "cricket",
  "dragon", "falcon", "feather", "fjord", "fox", "gadget", "gecko", "gizmo",
  "harbor", "heron", "iguana", "jelly", "koala", "lemur", "mango", "narwhal",
  "nebula", "noodle", "octopus", "otter", "panda", "pepper", "phoenix", "pickle",
  "puffin", "quokka", "radar", "ranger", "rocket", "scooter", "seahorse", "skylark",
  "sprocket", "starling", "sunbeam", "taco", "thimble", "tiger", "toucan", "triton",
  "walrus", "widget", "willow", "wombat", "yeti", "zeppelin", "zigzag", "zinnia",
] as const;

const exposeNameClosers = [
  "arcade", "beacon", "boogie", "bounce", "burst", "cascade", "chorus", "dash",
  "disco", "drift", "echo", "fiesta", "flare", "flash", "flight", "flip",
  "glow", "groove", "jam", "jive", "launch", "loop", "march", "orbit",
  "parade", "party", "pulse", "quest", "rally", "riot", "ripple", "rodeo",
  "roll", "rush", "serenade", "shuffle", "signal", "sketch", "spark", "sprint",
  "starlight", "stride", "sway", "swoop", "twirl", "uplift", "vibe", "voyage",
  "whirl", "wink", "zap", "zenith", "zip", "zoom", "zest", "zone",
] as const;

export function resolveExposeName(
  inputName: string,
  target: string,
  clientSeed: string
): string {
  const normalized = normalizeExposeName(inputName);
  if (normalized !== "") {
    return normalized;
  }
  return buildDefaultExposeName(target, clientSeed);
}

export function buildDefaultExposeName(
  target: string,
  clientSeed: string
): string {
  const seed = normalizeSeed(clientSeed);
  const normalizedTarget = normalizeExposeTarget(target);
  const [first, second, third] = pickNameIndexes(`${seed}|${normalizedTarget}`);
  const label = [
    exposeNameOpeners[first],
    exposeNameCenters[second],
    exposeNameClosers[third],
  ].join("-");

  return normalizeExposeName(label);
}

export function normalizeExposeName(value: string): string {
  const cleaned = sanitizeExposeNameInput(value);
  if (cleaned === "") {
    return "";
  }

  if (/^[a-z0-9-]+$/.test(cleaned)) {
    return cleaned.slice(0, 63);
  }

  const ascii = toASCIILabel(cleaned);
  if (ascii === "" || ascii.length > 63) {
    return "";
  }
  return ascii;
}

function normalizeExposeTarget(raw: string): string {
  const trimmed = raw.trim();
  const candidate = trimmed === "" ? DEFAULT_TARGET_PORT : trimmed;

  if (/^\d+$/.test(candidate)) {
    return `${DEFAULT_TARGET_HOST}:${candidate}`;
  }

  if (candidate.includes("://")) {
    try {
      const parsed = new URL(candidate);
      if (
        (parsed.protocol === "http:" || parsed.protocol === "https:") &&
        parsed.host !== "" &&
        (parsed.pathname === "" || parsed.pathname === "/") &&
        parsed.search === "" &&
        parsed.hash === ""
      ) {
        return parsed.host;
      }
    } catch {
      return candidate;
    }
  }

  try {
    const parsed = new URL(`tcp://${candidate}`);
    if (parsed.hostname === "") {
      return candidate;
    }
    const port = parsed.port || "80";
    if (parsed.hostname.includes(":")) {
      return `[${parsed.hostname}]:${port}`;
    }
    return `${parsed.hostname}:${port}`;
  } catch {
    return candidate;
  }
}

function normalizeSeed(clientSeed: string): string {
  const trimmed = clientSeed.trim();
  if (trimmed === "") {
    return "portal";
  }
  if (trimmed.startsWith("cli_")) {
    return trimmed.slice(4) || "portal";
  }
  return trimmed;
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

function pickNameIndexes(input: string): [number, number, number] {
  const [first, second, third] = hashBytes(input);
  return [
    first % exposeNameOpeners.length,
    second % exposeNameCenters.length,
    third % exposeNameClosers.length,
  ];
}

function hashBytes(input: string): [number, number, number] {
  const bytes = new TextEncoder().encode(input);
  const first = fnv1a32(bytes, 0x811c9dc5);
  const second = fnv1a32(bytes, 0x9e3779b9);
  const third = fnv1a32(bytes, 0x85ebca6b);

  return [first & 0xff, second & 0xff, third & 0xff];
}

function fnv1a32(bytes: Uint8Array, seed: number): number {
  let hash = seed >>> 0;
  for (const value of bytes) {
    hash ^= value;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}
