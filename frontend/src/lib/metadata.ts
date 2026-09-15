interface Metadata {
  description: string;
  tags: string[];
  thumbnail: string;
  owner: string;
  paymentEnabled: boolean;
  paymentLabel: string;
}

const EMPTY_METADATA: Metadata = {
  description: "",
  tags: [],
  thumbnail: "",
  owner: "",
  paymentEnabled: false,
  paymentLabel: "",
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
    paymentEnabled: value.payment_enabled === true,
    paymentLabel:
      typeof value.payment_label === "string" ? value.payment_label.trim() : "",
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

export function resolveLeaseThumbnail(metadata: Metadata): string {
  return metadata.thumbnail.trim();
}
