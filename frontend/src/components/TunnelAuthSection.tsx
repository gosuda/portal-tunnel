import {
  useEffect,
  useId,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import {
  Check,
  Copy,
  Globe,
  Link2,
  Lock,
  Mail,
  ShieldCheck,
  TriangleAlert,
  Wallet,
  X,
  type LucideIcon,
} from "lucide-react";
import type { TunnelAuthState } from "@/hooks/useTunnelCommand";
import { cn } from "@/lib/utils";
import {
  GOOGLE_OIDC_ISSUER,
  buildAuthIssueCommand,
  buildAuthRedirectURL,
  buildServiceStatusHostname,
  classifyAuthAllow,
  isHTTPSIssuer,
  type TunnelAuthMethod,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

type Theme = "light" | "terminal";

interface MethodChoice {
  id: TunnelAuthMethod | "email";
  label: string;
  short: string;
  description: string;
  icon: LucideIcon;
}

const METHODS: MethodChoice[] = [
  {
    id: "none",
    label: "Anyone with the link",
    short: "Anyone",
    description: "No sign-in. The address is the only secret.",
    icon: Globe,
  },
  {
    id: "credential",
    label: "Private link",
    short: "Private link",
    description: "You make one personal link per person. Nothing to set up.",
    icon: Link2,
  },
  {
    id: "siwe",
    label: "Ethereum wallet",
    short: "Wallet",
    description: "Visitors sign one message in their browser wallet.",
    icon: Wallet,
  },
  {
    id: "oidc",
    label: "Google or company login",
    short: "Google / company",
    description:
      "Visitors use an account they already have. You register an OAuth client first.",
    icon: ShieldCheck,
  },
  {
    id: "email",
    label: "Email link",
    short: "Email link",
    description: "A one-time link sent to the visitor's mailbox.",
    icon: Mail,
  },
];

const EXPIRY_CHOICES = [
  { value: "24h", label: "1 day" },
  { value: "168h", label: "7 days" },
  { value: "720h", label: "30 days" },
  { value: "2160h", label: "90 days" },
];

const ALLOW_COPY: Record<
  Exclude<TunnelAuthMethod, "none">,
  { label: string; requirement: string; placeholder: string; help: string }
> = {
  credential: {
    label: "Link names",
    requirement: "optional",
    placeholder: "alice, then Enter",
    help: "The names you will give links to. With names listed, you can cut someone off by removing their name.",
  },
  siwe: {
    label: "Allowed wallets",
    requirement: "optional",
    placeholder: "0x…, then Enter",
    help: "Ethereum addresses allowed to sign in.",
  },
  oidc: {
    label: "Who may sign in",
    requirement: "required",
    placeholder: "email, @domain or sub:id",
    help: "An email is one person. @example.com is everyone at exactly that domain, not its subdomains. sub:<id> is the provider's own account id.",
  },
};

const STYLES = {
  light: {
    label: "text-xs font-medium text-foreground dark:text-zinc-200",
    help: "text-xs leading-5 text-muted-foreground dark:text-zinc-500",
    card: "border-border bg-background hover:border-primary/50 dark:border-white/10 dark:bg-transparent",
    box: "border-border bg-background focus-within:border-ring focus-within:ring-1 focus-within:ring-ring/25 dark:border-white/10 dark:bg-transparent",
    input:
      "border-border bg-background text-foreground placeholder:text-muted-foreground dark:border-white/10 dark:bg-background dark:text-zinc-100 dark:placeholder:text-zinc-500",
    chip: "bg-secondary text-secondary-foreground dark:bg-primary/14 dark:text-primary",
    chipRemove: "hover:bg-background/80 dark:hover:bg-black/20",
    panel:
      "border-border bg-muted/45 dark:border-white/8 dark:bg-background/70",
    note: "bg-muted text-muted-foreground dark:bg-white/5 dark:text-zinc-400",
    code: "bg-secondary/55 text-foreground ring-1 ring-border/70 dark:bg-secondary/60 dark:text-zinc-100 dark:ring-transparent",
    copy: "text-text-muted hover:bg-background/70 dark:text-zinc-500 dark:hover:bg-black/20",
    error: "text-destructive",
    warn: "text-amber-700 dark:text-amber-400",
    preview: "border-border bg-card dark:border-white/10",
    previewButton: "bg-primary text-primary-foreground",
    strong: "text-foreground dark:text-zinc-100",
  },
  terminal: {
    label: "text-xs font-medium text-slate-200",
    help: "text-xs leading-5 text-slate-400",
    card: "border-white/10 bg-white/[0.03] hover:border-primary/60",
    box: "border-white/10 bg-white/5 focus-within:border-primary/70",
    input:
      "border-white/10 bg-white/5 text-white placeholder:text-slate-500",
    chip: "bg-white/10 text-slate-100",
    chipRemove: "hover:bg-white/10",
    panel: "border-white/10 bg-white/[0.03]",
    note: "bg-white/5 text-slate-400",
    code: "bg-black/40 text-white ring-1 ring-white/10",
    copy: "text-slate-400 hover:bg-white/10",
    error: "text-red-300",
    warn: "text-amber-300",
    preview: "border-white/10 bg-white/[0.04]",
    previewButton: "bg-primary text-primary-foreground",
    strong: "text-slate-100",
  },
} as const;

/** One line for the collapsed hero row, e.g. "Private link · 2 names". */
export function describeAuth(auth: TunnelAuthState): string {
  const label = METHODS.find((method) => method.id === auth.method)?.label ?? "";
  const count = auth.allow[auth.method].length;
  if (auth.method === "none") {
    return label;
  }
  if (count === 0) {
    return auth.method === "oidc" ? `${label} · no list yet` : `${label} · open list`;
  }
  return `${label} · ${count} ${count === 1 ? "entry" : "entries"}`;
}

interface TunnelAuthSectionProps {
  auth: TunnelAuthState;
  onChange: (next: TunnelAuthState) => void;
  currentOrigin: string;
  /** The normalized public name; empty while the user has not chosen one. */
  name: string;
  os: TunnelCommandOS;
  theme: Theme;
  /** Pills instead of cards and no visitor preview, for the narrow hero card. */
  compact?: boolean;
}

export function TunnelAuthSection({
  auth,
  onChange,
  currentOrigin,
  name,
  os,
  theme,
  compact = false,
}: TunnelAuthSectionProps) {
  const groupId = useId();
  const s = STYLES[theme];
  const patch = (next: Partial<TunnelAuthState>) =>
    onChange({ ...auth, ...next });

  const selectable = METHODS.filter((method) => method.id !== "email");
  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const step =
      event.key === "ArrowRight" || event.key === "ArrowDown"
        ? 1
        : event.key === "ArrowLeft" || event.key === "ArrowUp"
          ? -1
          : 0;
    if (step === 0) {
      return;
    }
    event.preventDefault();
    const index = selectable.findIndex((method) => method.id === auth.method);
    const next =
      selectable[(index + step + selectable.length) % selectable.length];
    if (!next) {
      return;
    }
    patch({ method: next.id as TunnelAuthMethod });
    document.getElementById(`${groupId}-${next.id}`)?.focus();
  };

  return (
    <div className="space-y-3">
      <div
        role="radiogroup"
        aria-label="Who can open it"
        onKeyDown={handleKeyDown}
        className={cn(
          compact ? "flex flex-wrap gap-1.5" : "grid gap-2 sm:grid-cols-2"
        )}
      >
        {METHODS.map((method) => {
          const soon = method.id === "email";
          const selected = method.id === auth.method;
          const Icon = method.icon;
          return (
            <button
              key={method.id}
              id={`${groupId}-${method.id}`}
              type="button"
              role="radio"
              aria-checked={selected}
              aria-disabled={soon || undefined}
              tabIndex={selected ? 0 : -1}
              onClick={() => {
                if (!soon) {
                  patch({ method: method.id as TunnelAuthMethod });
                }
              }}
              className={cn(
                "border text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                compact
                  ? "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold"
                  : "grid grid-cols-[auto_1fr] content-start gap-x-2.5 gap-y-0.5 rounded-lg px-3 py-2.5",
                s.card,
                selected && "border-primary bg-primary/10 ring-1 ring-primary",
                soon && "cursor-not-allowed border-dashed opacity-60"
              )}
            >
              <Icon
                aria-hidden="true"
                className={cn(
                  compact ? "h-3.5 w-3.5" : "row-span-2 mt-0.5 h-4 w-4",
                  selected && "text-primary"
                )}
              />
              <span
                className={cn(
                  "flex flex-wrap items-center gap-1.5",
                  !compact && "text-[13px] font-semibold"
                )}
              >
                {compact ? method.short : method.label}
                {method.id === "oidc" && !compact && (
                  <span
                    className={cn(
                      "rounded px-1.5 py-px text-[10px] font-semibold uppercase",
                      s.chip
                    )}
                  >
                    OpenID Connect
                  </span>
                )}
                {soon && (
                  <span
                    className={cn(
                      "rounded px-1.5 py-px text-[10px] font-semibold uppercase",
                      s.chip
                    )}
                  >
                    Coming soon
                  </span>
                )}
              </span>
              {!compact && (
                <span className={cn("col-start-2", s.help)}>
                  {method.description}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {auth.method === "none" ? (
        <p className={s.help}>
          Anyone who learns the address can open the app. Choose a sign-in
          method to limit it.
        </p>
      ) : (
        <div className={cn("space-y-4 rounded-lg border p-3", s.panel)}>
          <AllowList key={auth.method} auth={auth} patch={patch} theme={theme} />
          {auth.method === "oidc" && (
            <OIDCSetup
              auth={auth}
              patch={patch}
              currentOrigin={currentOrigin}
              name={name}
              theme={theme}
            />
          )}
          {auth.method === "credential" && (
            <InviteBlock
              currentOrigin={currentOrigin}
              name={name}
              os={os}
              theme={theme}
            />
          )}
          <label
            className={cn(
              "flex cursor-pointer items-start gap-2 text-[13px]",
              s.strong
            )}
          >
            <input
              type="checkbox"
              checked={auth.identityHeaders}
              onChange={(event) =>
                patch({ identityHeaders: event.target.checked })
              }
              className="mt-0.5 h-4 w-4"
            />
            <span>
              Pass the visitor's identity to my app
              <span className={cn("block", s.help)}>
                Adds <code>X-Portal-User</code> and <code>X-Portal-Auth</code>.
                Only safe if the app can be reached through Portal alone.
              </span>
            </span>
          </label>
        </div>
      )}

      {!compact && auth.method !== "none" && (
        <VisitorPreview
          auth={auth}
          currentOrigin={currentOrigin}
          name={name}
          theme={theme}
        />
      )}
    </div>
  );
}

function AllowList({
  auth,
  patch,
  theme,
}: {
  auth: TunnelAuthState;
  patch: (next: Partial<TunnelAuthState>) => void;
  theme: Theme;
}) {
  const inputId = useId();
  const [draft, setDraft] = useState("");
  const s = STYLES[theme];
  const method = auth.method;
  if (method === "none") {
    return null;
  }
  const copy = ALLOW_COPY[method];
  const entries = auth.allow[method];
  const checks = entries.map((entry) => classifyAuthAllow(method, entry));

  const setEntries = (next: string[]) =>
    patch({ allow: { ...auth.allow, [method]: next } });
  const commitDraft = () => {
    const parts = draft.split(/[,\s]+/).filter((part) => part !== "");
    if (parts.length === 0) {
      return;
    }
    setEntries([
      ...entries,
      ...new Set(parts.filter((part) => !entries.includes(part))),
    ]);
    setDraft("");
  };
  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter" || event.key === ",") {
      event.preventDefault();
      commitDraft();
    } else if (event.key === "Backspace" && draft === "" && entries.length > 0) {
      setEntries(entries.slice(0, -1));
    }
  };

  return (
    <div className="space-y-1.5">
      <label htmlFor={inputId} className={s.label}>
        {copy.label}{" "}
        <span className="font-normal opacity-70">({copy.requirement})</span>
      </label>
      <div
        className={cn(
          "flex min-h-9 flex-wrap items-center gap-1.5 rounded-md border px-1.5 py-1.5",
          s.box
        )}
      >
        {entries.map((entry, index) => {
          const check = checks[index];
          const bad = check !== undefined && !check.ok;
          return (
            <span
              key={entry}
              className={cn(
                "inline-flex max-w-full items-center gap-1.5 rounded-md py-0.5 pl-2 pr-0.5 text-xs",
                s.chip,
                bad && "ring-1 ring-destructive"
              )}
            >
              <span
                className={cn(
                  "text-[10px] font-semibold uppercase",
                  bad ? s.error : "text-primary"
                )}
              >
                {check?.ok ? check.kind : "invalid"}
              </span>
              <code className="break-all">{entry}</code>
              <button
                type="button"
                aria-label={`Remove ${entry}`}
                onClick={() =>
                  setEntries(entries.filter((candidate) => candidate !== entry))
                }
                className={cn("rounded p-0.5", s.chipRemove)}
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          );
        })}
        <input
          id={inputId}
          type="text"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={handleKeyDown}
          onBlur={commitDraft}
          placeholder={copy.placeholder}
          autoComplete="off"
          spellCheck={false}
          className="min-w-[140px] flex-1 bg-transparent px-1 text-sm outline-none placeholder:opacity-60"
        />
      </div>
      <p className={s.help}>{copy.help}</p>
      {checks.map(
        (check, index) =>
          !check.ok && (
            <Notice key={entries[index]} tone="error" theme={theme}>
              {check.error}
            </Notice>
          )
      )}
      {entries.length === 0 && method === "oidc" && (
        <Notice tone="error" theme={theme}>
          Add at least one. Without a list Portal refuses to start, because the
          provider signs in people who have nothing to do with your app.
        </Notice>
      )}
      {entries.length === 0 && method === "siwe" && (
        <Notice tone="warn" theme={theme}>
          No list: any wallet that signs in gets through. That proves a wallet
          exists, not who owns it.
        </Notice>
      )}
      {entries.length === 0 && method === "credential" && (
        <Notice tone="warn" theme={theme}>
          No names: every unexpired link works, and a link can't be revoked
          before it expires.
        </Notice>
      )}
    </div>
  );
}

function OIDCSetup({
  auth,
  patch,
  currentOrigin,
  name,
  theme,
}: {
  auth: TunnelAuthState;
  patch: (next: Partial<TunnelAuthState>) => void;
  currentOrigin: string;
  name: string;
  theme: Theme;
}) {
  const issuerId = useId();
  const clientId = useId();
  const s = STYLES[theme];
  const isGoogle = auth.oidcIssuer === GOOGLE_OIDC_ISSUER;
  const issuerInvalid =
    auth.oidcIssuer.trim() !== "" && !isHTTPSIssuer(auth.oidcIssuer);
  const redirectURL = buildAuthRedirectURL(currentOrigin, name);
  const inputClass = cn(
    "h-9 w-full rounded-md border px-3 font-mono text-[13px] outline-none focus-visible:ring-1 focus-visible:ring-ring read-only:opacity-70",
    s.input
  );

  return (
    <div className="space-y-4">
      <div className="space-y-1.5">
        <span className={s.label}>Provider</span>
        <div className="flex gap-1.5" role="radiogroup" aria-label="Provider">
          {[
            { id: "google", label: "Google", active: isGoogle },
            { id: "other", label: "Another provider", active: !isGoogle },
          ].map((choice) => (
            <button
              key={choice.id}
              type="button"
              role="radio"
              aria-checked={choice.active}
              onClick={() =>
                patch({
                  oidcIssuer: choice.id === "google" ? GOOGLE_OIDC_ISSUER : "",
                })
              }
              className={cn(
                "rounded-full border px-3 py-1 text-xs font-semibold transition-colors",
                s.card,
                choice.active && "border-primary bg-primary/10 ring-1 ring-primary"
              )}
            >
              {choice.label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-3">
        <div className="space-y-1.5">
          <label htmlFor={issuerId} className={s.label}>
            Issuer
          </label>
          <input
            id={issuerId}
            type="text"
            value={auth.oidcIssuer}
            readOnly={isGoogle}
            onChange={(event) => patch({ oidcIssuer: event.target.value })}
            placeholder="https://login.example.com"
            autoComplete="off"
            spellCheck={false}
            className={inputClass}
          />
          {issuerInvalid && (
            <Notice tone="error" theme={theme}>
              The issuer must be an https:// address.
            </Notice>
          )}
          {!isGoogle && (
            <p className={s.help}>
              Any provider that publishes{" "}
              <code>/.well-known/openid-configuration</code>. GitHub does not:
              its login is not OpenID Connect.
            </p>
          )}
        </div>
        <div className="space-y-1.5">
          <label htmlFor={clientId} className={s.label}>
            Client ID
          </label>
          <input
            id={clientId}
            type="text"
            value={auth.oidcClientId}
            onChange={(event) => patch({ oidcClientId: event.target.value })}
            placeholder="abc.apps.googleusercontent.com"
            autoComplete="off"
            spellCheck={false}
            className={inputClass}
          />
        </div>
      </div>

      <p className={cn("flex gap-2 rounded-md p-2.5 text-xs", s.note)}>
        <Lock aria-hidden="true" className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span>
          <strong className={s.strong}>
            The client secret is not entered here.
          </strong>{" "}
          The command sets it from <code>AUTH_OIDC_CLIENT_SECRET</code> on its
          own line, which keeps it out of the process list and your shell
          history.
        </span>
      </p>

      <div className="space-y-1.5">
        <p className={s.label}>At your provider, before you run the command</p>
        <p className={s.help}>
          Create an OAuth client for a web application and add this redirect
          address:
        </p>
        {redirectURL === "" ? (
          <Notice tone="warn" theme={theme}>
            Add a Name first. The provider needs the exact address, and it is
            built from the Name.
          </Notice>
        ) : (
          <CopyLine value={redirectURL} label="Copy redirect address" theme={theme} />
        )}
      </div>
    </div>
  );
}

function InviteBlock({
  currentOrigin,
  name,
  os,
  theme,
}: {
  currentOrigin: string;
  name: string;
  os: TunnelCommandOS;
  theme: Theme;
}) {
  const subjectId = useId();
  const expiresId = useId();
  const s = STYLES[theme];
  const [subject, setSubject] = useState("");
  const [expires, setExpires] = useState("720h");
  const command = buildAuthIssueCommand({
    origin: currentOrigin,
    name,
    subject,
    expires,
    os,
  });
  const fieldClass = cn(
    "h-9 w-full rounded-md border px-3 text-[13px] outline-none focus-visible:ring-1 focus-visible:ring-ring",
    s.input
  );

  return (
    <div className="space-y-2">
      <p className={s.label}>After it runs: invite someone</p>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5">
          <label htmlFor={subjectId} className={s.label}>
            Name
          </label>
          <input
            id={subjectId}
            type="text"
            value={subject}
            onChange={(event) => setSubject(event.target.value)}
            placeholder="alice"
            autoComplete="off"
            spellCheck={false}
            className={cn(fieldClass, "font-mono")}
          />
        </div>
        <div className="space-y-1.5">
          <label htmlFor={expiresId} className={s.label}>
            Valid for
          </label>
          <select
            id={expiresId}
            value={expires}
            onChange={(event) => setExpires(event.target.value)}
            className={fieldClass}
          >
            {EXPIRY_CHOICES.map((choice) => (
              <option key={choice.value} value={choice.value}>
                {choice.label}
              </option>
            ))}
          </select>
        </div>
      </div>
      {command === "" ? (
        <p className={s.help}>
          {name === ""
            ? "Add a Name above, then a name for the person, to see the command."
            : "Type the person's name to see the command."}
        </p>
      ) : (
        <CopyLine value={command} label="Copy invite command" theme={theme} />
      )}
      <p className={s.help}>
        It prints a link to send to that person. Anyone who holds the link gets
        in until it expires, so send it privately.
      </p>
    </div>
  );
}

function VisitorPreview({
  auth,
  currentOrigin,
  name,
  theme,
}: {
  auth: TunnelAuthState;
  currentOrigin: string;
  name: string;
  theme: Theme;
}) {
  const s = STYLES[theme];
  const hostname =
    buildServiceStatusHostname(currentOrigin, name) || "your-name.relay";
  let issuerHost = "your provider";
  try {
    issuerHost = new URL(auth.oidcIssuer.trim()).hostname || issuerHost;
  } catch {
    // The issuer is still being typed.
  }
  const page = {
    credential: {
      title: "Sign in to continue",
      body: "Paste the access credential the owner of this app gave you.",
      action: "Sign in",
    },
    siwe: {
      title: "Connect your wallet",
      body: "Sign a one-time message to show you own an allowed Ethereum address. It costs nothing.",
      action: "Connect wallet",
    },
    oidc: {
      title: `You are sent to ${issuerHost}`,
      body: "They sign in there and come back to the app.",
      action: "",
    },
    none: { title: "", body: "", action: "" },
  }[auth.method];

  return (
    <div className="space-y-1.5">
      <div
        aria-hidden="true"
        className={cn("rounded-lg border px-4 py-5 text-center", s.preview)}
      >
        <span
          className={cn(
            "inline-block rounded-full px-2.5 py-0.5 font-mono text-[11px]",
            s.chip
          )}
        >
          {hostname}
        </span>
        <p className={cn("mt-2 text-sm font-semibold", s.strong)}>
          {page.title}
        </p>
        <p className={cn("mx-auto mt-1 max-w-[36ch]", s.help)}>{page.body}</p>
        {page.action !== "" && (
          <span
            className={cn(
              "mt-3 inline-block rounded-md px-4 py-1.5 text-xs font-bold",
              s.previewButton
            )}
          >
            {page.action}
          </span>
        )}
      </div>
      <p className={cn("text-center", s.help)}>
        What a visitor sees first (illustrative)
      </p>
    </div>
  );
}

function CopyLine({
  value,
  label,
  theme,
}: {
  value: string;
  label: string;
  theme: Theme;
}) {
  const [copied, setCopied] = useState(false);
  const s = STYLES[theme];

  useEffect(() => {
    if (!copied) {
      return;
    }
    const timer = window.setTimeout(() => setCopied(false), 2000);
    return () => window.clearTimeout(timer);
  }, [copied]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch (error) {
      console.error("Failed to copy", error);
    }
  };

  return (
    <div
      className={cn(
        "flex items-center gap-1 rounded-md py-1 pl-3 pr-1 font-mono text-xs",
        s.code
      )}
    >
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap py-1">
        {value}
      </code>
      <button
        type="button"
        onClick={handleCopy}
        aria-label={label}
        title={copied ? "Copied" : "Copy"}
        className={cn("shrink-0 rounded-md p-2 transition-colors", s.copy)}
      >
        {copied ? (
          <Check className="h-4 w-4 text-emerald-500" />
        ) : (
          <Copy className="h-4 w-4" />
        )}
      </button>
    </div>
  );
}

function Notice({
  tone,
  theme,
  children,
}: {
  tone: "error" | "warn";
  theme: Theme;
  children: ReactNode;
}) {
  const s = STYLES[theme];
  return (
    <p
      className={cn(
        "flex items-start gap-1.5 text-xs leading-5",
        tone === "error" ? s.error : s.warn
      )}
    >
      <TriangleAlert aria-hidden="true" className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span>{children}</span>
    </p>
  );
}
