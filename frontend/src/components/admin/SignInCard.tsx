import { useState } from "react";
import { KeyRound, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { AdminAuth } from "@/hooks/useAuth";

export function SignInCard({ login }: Pick<AdminAuth, "login">) {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const submit = async () => {
    setError("");
    setSubmitting(true);
    const result = await login(token);
    setSubmitting(false);
    if (!result.success) {
      setError(result.error || "Admin login failed.");
    }
  };

  return (
    <form
      className="mx-auto mt-16 flex w-full max-w-sm flex-col gap-4 rounded-lg border border-stroke bg-surface-100 p-6"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <KeyRound className="size-10 text-content-muted" aria-hidden />
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-bold text-content-emphasis">Admin sign-in</h1>
        <p className="text-sm text-content-muted">Enter the admin token to view admin controls.</p>
      </div>
      <Input
        type="password"
        value={token}
        onChange={(event) => setToken(event.target.value)}
        placeholder="Admin token"
        aria-label="Admin token"
        autoComplete="current-password"
        disabled={submitting}
      />
      {error && (
        <p role="alert" className="text-sm font-medium text-danger">
          {error}
        </p>
      )}
      <Button type="submit" variant="primary" disabled={submitting}>
        {submitting && <Loader2 className="size-4 motion-safe:animate-spin" aria-hidden />}
        Sign in
      </Button>
    </form>
  );
}
