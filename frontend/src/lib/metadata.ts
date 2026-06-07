import { BROWSER_API_PATHS } from "./apiPaths.js";

interface Metadata {
  description: string;
  tags: string[];
  thumbnail: string;
  owner: string;
}

const EMPTY_METADATA: Metadata = {
  description: "",
  tags: [],
  thumbnail: "",
  owner: "",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function metadataFromRecord(value: Record<string, unknown>): Metadata {
  return {
    description: typeof value.description === "string" ? value.description : "",
    tags: Array.isArray(value.tags)
      ? value.tags
          .map((tag) => (typeof tag === "string" ? tag.trim() : ""))
          .filter(Boolean)
      : [],
    thumbnail: typeof value.thumbnail === "string" ? value.thumbnail : "",
    owner: typeof value.owner === "string" ? value.owner : "",
  };
}

export function parseLeaseMetadata(metadataValue: unknown): Metadata {
  if (!metadataValue) {
    return EMPTY_METADATA;
  }

  if (isRecord(metadataValue)) {
    return metadataFromRecord(metadataValue);
  }

  if (typeof metadataValue !== "string") {
    return EMPTY_METADATA;
  }

  try {
    const parsed = JSON.parse(metadataValue);
    if (!isRecord(parsed)) {
      return EMPTY_METADATA;
    }

    return metadataFromRecord(parsed);
  } catch {
    return EMPTY_METADATA;
  }
}

export function resolveLeaseThumbnail(metadata: Metadata, hostname: string): string {
  const configuredThumbnail = metadata.thumbnail.trim();
  if (configuredThumbnail !== "") {
    return configuredThumbnail;
  }

  const normalizedHostname = hostname.trim().toLowerCase().replace(/\.$/, "");
  if (normalizedHostname === "" || normalizedHostname.startsWith("*.")) {
    return "";
  }
  return `${BROWSER_API_PATHS.thumbnail.prefix}${encodeURIComponent(normalizedHostname)}`;
}
