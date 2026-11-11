import type { JSX } from "react";
import { useId, useState } from "react";
import { Chip, ChipField, Notice, TUNNEL_FORM_STYLES as s } from "@/components/TunnelFormParts";
import { ALLOW_COPY, FieldIssues } from "./authShared";
import {
  addAuthAllow,
  classifyAuthAllow,
  type TunnelAuthIssue,
  type TunnelAuthOptions,
} from "@/lib/tunnelCommand";

export function AllowList({
  auth,
  patch,
  issues,
}: {
  auth: TunnelAuthOptions;
  patch: (next: Partial<TunnelAuthOptions>) => void;
  issues: TunnelAuthIssue[];
}): JSX.Element | null {
  const inputId = useId();
  const [draft, setDraft] = useState("");
  const method = auth.method;
  if (method === "none") {
    return null;
  }
  const copy = ALLOW_COPY[method];

  const commitDraft = () => {
    patch({ allow: addAuthAllow(method, auth.allow, draft) });
    setDraft("");
  };
  const removeEntry = (entry: string) =>
    patch({ allow: auth.allow.filter((candidate) => candidate !== entry) });

  return (
    <div className="space-y-1.5">
      <label htmlFor={inputId} className={s.label}>
        {copy.label}{" "}
        <span className="font-normal opacity-70">({copy.requirement})</span>
      </label>
      <ChipField
        id={inputId}
        draft={draft}
        placeholder={copy.placeholder}
        commitKeys={["Enter", ","]}
        commitOnBlur
        onDraftChange={setDraft}
        onCommit={commitDraft}
        onRemoveLast={() => patch({ allow: auth.allow.slice(0, -1) })}
        chips={auth.allow.map((entry) => {
          const check = classifyAuthAllow(method, entry);
          return (
            <Chip
              key={entry}
              text={entry}
              kind={check.ok ? check.kind : "invalid"}
              invalid={!check.ok}
              removeLabel={`Remove ${entry}`}
              onRemove={() => removeEntry(entry)}
            />
          );
        })}
      />
      <p className={s.help}>{copy.help}</p>
      {auth.allow.map((entry) => {
        const check = classifyAuthAllow(method, entry);
        return (
          !check.ok && (
            <Notice key={entry} tone="error">
              {check.error}
            </Notice>
          )
        );
      })}
      <FieldIssues issues={issues} field="allow" />
      <div role="status">
        {auth.allow.length === 0 && method === "siwe" && (
          <Notice tone="warn">
            The list is empty, so any wallet that signs in gets through, which
            proves a wallet exists, not who owns it. Removing the last address
            does not end its access: stop the tunnel instead (or list a
            placeholder address nobody will use).
          </Notice>
        )}
        {auth.allow.length === 0 && method === "credential" && (
          <Notice tone="warn">
            The list is empty, so every unexpired link works and none can be
            revoked before it expires. Removing the last name does not end its
            access: stop the tunnel instead (or list a name no link was issued
            for).
          </Notice>
        )}
      </div>
    </div>
  );
}
