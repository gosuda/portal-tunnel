interface Metadata {
  description: string;
  tags: string[];
  thumbnail: string;
  owner: string;
}

export interface PaymentDisplay {
  enabled: boolean;
  label: string;
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

export function resolveLeaseThumbnail(metadata: Metadata): string {
  return metadata.thumbnail.trim();
}

export function resolveLeasePayment(metadata: Metadata): PaymentDisplay {
  const normalizedTags = new Set(
    metadata.tags.map((tag) => tag.trim().toLowerCase()).filter(Boolean)
  );
  const description = metadata.description.toLowerCase();
  const enabled =
    normalizedTags.has("x402") ||
    normalizedTags.has("payment") ||
    normalizedTags.has("paid") ||
    normalizedTags.has("usdc") ||
    /\bx402\b|\bpaid\b|\bpayment\b|\busdc\b/.test(description);

  if (!enabled) {
    return { enabled: false, label: "" };
  }

  const labelParts: string[] = [];
  if (normalizedTags.has("x402") || description.includes("x402")) {
    labelParts.push("x402");
  }
  if (normalizedTags.has("usdc") || description.includes("usdc")) {
    labelParts.push("USDC");
  }

  return {
    enabled: true,
    label: labelParts.length > 0 ? labelParts.join(" ") : "Paid app",
  };
}
