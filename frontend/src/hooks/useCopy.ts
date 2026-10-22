import { useEffect, useState } from "react";

/**
 * Copies text to the clipboard and reports which key was copied until it
 * resets, so one control (or one of several) can show "Copied".
 */
export function useCopy(resetMs = 2000) {
  // A new object on every copy restarts the reset timer, even for the same key.
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
      // Clipboard access can be denied outside a secure, user-initiated context.
      console.error("Failed to copy", error);
    }
  };

  return { copiedKey: copied?.key ?? null, copy };
}
