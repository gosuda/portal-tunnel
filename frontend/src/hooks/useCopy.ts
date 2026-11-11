import { useEffect, useState } from "react";

export function useCopy(resetMs: number = 2000): { copiedKey: string | null; copy: (text: string, key?: string) => Promise<void> } {
  const [copied, setCopied] = useState<{ key: string } | null>(null);

  useEffect(() => {
    if (copied === null) {
      return;
    }

    const timer = window.setTimeout(() => setCopied(null), resetMs);
    return () => window.clearTimeout(timer);
  }, [copied, resetMs]);

  const copy = async (text: string, key = "") => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied({ key });
    } catch (error) {
      console.error("Failed to copy", error);
    }
  };

  return { copiedKey: copied?.key ?? null, copy };
}
