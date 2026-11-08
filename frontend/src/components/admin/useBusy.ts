import { useState } from "react";

export function useBusy() {
  const [busy, setBusy] = useState(false);
  const run = async (action: () => Promise<void>): Promise<boolean> => {
    setBusy(true);
    try {
      await action();
      return true;
    } catch {
      return false;
    } finally {
      setBusy(false);
    }
  };
  return { busy, run };
}
