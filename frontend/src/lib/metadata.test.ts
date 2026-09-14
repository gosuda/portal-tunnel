import { describe, expect, it } from "vitest";
import { parseLeaseMetadata } from "@/lib/metadata";

describe("parseLeaseMetadata explicit payment contract", () => {
  it("parses payment_enabled and trims payment_label from a record", () => {
    const metadata = parseLeaseMetadata({
      description: "test",
      tags: [],
      thumbnail: "",
      owner: "",
      payment_enabled: true,
      payment_label: " x402 USDC ",
    });
    expect(metadata.paymentEnabled).toBe(true);
    expect(metadata.paymentLabel).toBe("x402 USDC");
  });

  it("parses payment_enabled and trims payment_label from JSON-string metadata", () => {
    const metadata = parseLeaseMetadata(
      JSON.stringify({
        description: "test",
        tags: [],
        thumbnail: "",
        owner: "",
        payment_enabled: true,
        payment_label: " x402 USDC ",
      })
    );
    expect(metadata.paymentEnabled).toBe(true);
    expect(metadata.paymentLabel).toBe("x402 USDC");
  });

  it("does not enable payment from tags like x402, paid, usdc without payment_enabled", () => {
    const metadata = parseLeaseMetadata({
      description: "x402 paid usdc payment",
      tags: ["x402", "paid", "usdc", "payment"],
      thumbnail: "",
      owner: "",
    });
    expect(metadata.paymentEnabled).toBe(false);
    expect(metadata.paymentLabel).toBe("");
  });

  it("does not enable payment from description text without payment_enabled", () => {
    const metadata = parseLeaseMetadata({
      description: "This app requires x402 USDC payment",
      tags: [],
      thumbnail: "",
      owner: "",
    });
    expect(metadata.paymentEnabled).toBe(false);
    expect(metadata.paymentLabel).toBe("");
  });

  it("defaults payment to disabled when fields are absent", () => {
    const metadata = parseLeaseMetadata({
      description: "test",
      tags: [],
      thumbnail: "",
      owner: "",
    });
    expect(metadata.paymentEnabled).toBe(false);
    expect(metadata.paymentLabel).toBe("");
  });

  it("returns empty metadata for null/undefined input", () => {
    expect(parseLeaseMetadata(null).paymentEnabled).toBe(false);
    expect(parseLeaseMetadata(undefined).paymentEnabled).toBe(false);
    expect(parseLeaseMetadata("").paymentEnabled).toBe(false);
  });
});
