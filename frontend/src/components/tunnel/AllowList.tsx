import { useId, useState } from "react";
import { ChipInput, FieldIssues, Hint, LABEL, Notice } from "./fields";
import {
  addAuthAllow,
  classifyAuthAllow,
  type TunnelAuthIssue,
  type TunnelAuthMethod,
  type TunnelAuthOptions,
} from "@/lib/tunnelCommand";

const ALLOW_COPY: Record<
  Exclude<TunnelAuthMethod, "none">,
  { label: string; requirement: string; placeholder: string; help: string }
> = {
  credential: {
    label: "Link names",
    requirement: "optional",
    placeholder: "alice, then Enter",
    help: "The names you will give links to; separate several with commas (a name cannot contain one). With names listed, only those names get in. Removing the last name leaves the list empty, which lets every unexpired link in: to end access for the last person, stop the tunnel instead.",
  },
  siwe: {
    label: "Allowed wallets",
    requirement: "optional",
    placeholder: "0x…, then Enter",
    help: "Ethereum addresses allowed to sign in. Removing the last address leaves the list empty, which lets any wallet in: to end access for the last person, stop the tunnel instead.",
  },
  oidc: {
    label: "Who may sign in",
    requirement: "required",
    placeholder: "email, @domain or sub:id",
    help: "Separate several with commas. An email is one person. @example.com is everyone at exactly that domain, not its subdomains. sub:<id> is the provider's own account id. Portal refuses to start without a list, because the provider signs in people who have nothing to do with your app.",
  },
  saml: {
    label: "Who may sign in",
    requirement: "required",
    placeholder: "email, @domain or sub:id",
    help: "Separate several with commas. Each entry is matched against the subject the provider signs: the NameID, or the attribute you name below. An email is one person and @example.com everyone at exactly that domain, when the subject is an email. sub:<id> is the subject exactly as the provider sends it. Portal refuses to start without a list, because the provider signs in people who have nothing to do with your app.",
  },
  email: {
    label: "Who may sign in",
    requirement: "required",
    placeholder: "email or @domain",
    help: "Separate several with commas. An email is one person. @example.com is everyone at exactly that domain, not its subdomains. Only these addresses get a link. Portal refuses to start without a list, because anyone could otherwise make the tunnel send mail to any address.",
  },
};

export function AllowList({
  auth,
  patch,
  issues,
}: {
  auth: TunnelAuthOptions;
  patch: (next: Partial<TunnelAuthOptions>) => void;
  issues: TunnelAuthIssue[];
}) {
  const inputId = useId();
  const [draft, setDraft] = useState("");
  const method = auth.method;
  if (method === "none") {
    return null;
  }
  const copy = ALLOW_COPY[method];
  const checks = auth.allow.map((entry) => ({
    entry,
    check: classifyAuthAllow(method, entry),
  }));

  return (
    <div className="space-y-1.5">
      <label htmlFor={inputId} className={LABEL}>
        {copy.label}{" "}
        <span className="font-normal text-content-muted">
          ({copy.requirement})
        </span>
      </label>
      <ChipInput
        id={inputId}
        draft={draft}
        placeholder={copy.placeholder}
        commitKeys={["Enter", ","]}
        commitOnBlur
        onDraftChange={setDraft}
        onCommit={() => {
          patch({ allow: addAuthAllow(method, auth.allow, draft) });
          setDraft("");
        }}
        onRemoveLast={() => patch({ allow: auth.allow.slice(0, -1) })}
        chips={checks.map(({ entry, check }) => ({
          text: entry,
          kind: check.ok ? check.kind : "invalid",
          invalid: !check.ok,
          removeLabel: `Remove ${entry}`,
          onRemove: () =>
            patch({ allow: auth.allow.filter((other) => other !== entry) }),
        }))}
      />
      <Hint>{copy.help}</Hint>
      {checks.map(
        ({ entry, check }) =>
          !check.ok && (
            <Notice key={entry} tone="error">
              {check.error}
            </Notice>
          )
      )}
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
