import { useId, useState, type KeyboardEvent, type ReactNode } from "react";
import {
  Check,
  Copy,
  Globe,
  Link2,
  Mail,
  ShieldCheck,
  Wallet,
  type LucideIcon,
} from "lucide-react";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Chip,
  ChipField,
  Notice,
  TUNNEL_FORM_STYLES,
  type TunnelFormTheme,
} from "@/components/TunnelFormParts";
import { useCopy } from "@/hooks/useCopy";
import { cn } from "@/lib/utils";
import {
  GOOGLE_OIDC_ISSUER,
  addAuthAllow,
  buildAuthIssueCommand,
  buildAuthRedirectURL,
  buildOIDCSecretCommand,
  buildServiceStatusHostname,
  classifyAuthAllow,
  type TunnelAuthField,
  type TunnelAuthIssue,
  type TunnelAuthMethod,
  type TunnelAuthOptions,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

interface MethodChoice<Id extends string> {
  id: Id;
  label: string;
  short: string;
  description: string;
  icon: LucideIcon;
}

const METHODS: MethodChoice<TunnelAuthMethod>[] = [
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
];

// Shown disabled until the tunnel accepts `--auth email` (#666).
const EMAIL_METHOD: MethodChoice<"email"> = {
  id: "email",
  label: "Email link",
  short: "Email link",
  description: "A one-time link sent to the visitor's mailbox.",
  icon: Mail,
};

const EXPIRY_CHOICES = [
  { value: "24h", label: "1 day" },
  { value: "168h", label: "7 days" },
  { value: "720h", label: "30 days" },
  { value: "2160h", label: "90 days" },
];

const SELECTED = "border-primary bg-primary/10 ring-1 ring-primary";

const ALLOW_COPY: Record<
  Exclude<TunnelAuthMethod, "none">,
  { label: string; requirement: string; placeholder: string; help: string }
> = {
  credential: {
    label: "Link names",
    requirement: "optional",
    placeholder: "alice, then Enter",
    help: "The names you will give links to; separate several with commas. With names listed, you can cut someone off by removing their name.",
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
    help: "An email is one person. @example.com is everyone at exactly that domain, not its subdomains. sub:<id> is the provider's own account id. Portal refuses to start without a list, because the provider signs in people who have nothing to do with your app.",
  },
};

/** One line for the collapsed hero row, e.g. "Private link · 2 entries". */
export function describeAuth(auth: TunnelAuthOptions): string {
  const label = METHODS.find((method) => method.id === auth.method)?.label ?? "";
  const count = auth.allow.length;
  if (auth.method === "none") {
    return label;
  }
  if (count === 0) {
    return `${label} · ${auth.method === "oidc" ? "no list yet" : "open list"}`;
  }
  return `${label} · ${count} ${count === 1 ? "entry" : "entries"}`;
}

interface TunnelAuthSectionProps {
  auth: TunnelAuthOptions;
  onChange: (next: TunnelAuthOptions) => void;
  /** From validateTunnelAuth; the same list that gates copying the command. */
  issues: TunnelAuthIssue[];
  currentOrigin: string;
  /** The normalized public name; empty while the user has not chosen one. */
  name: string;
  os: TunnelCommandOS;
  theme: TunnelFormTheme;
  /** Pills instead of cards and no visitor preview, for the narrow hero card. */
  compact?: boolean;
}

export function TunnelAuthSection({
  auth,
  onChange,
  issues,
  currentOrigin,
  name,
  os,
  theme,
  compact = false,
}: TunnelAuthSectionProps) {
  const groupId = useId();
  const s = TUNNEL_FORM_STYLES[theme];
  const patch = (next: Partial<TunnelAuthOptions>) =>
    onChange({ ...auth, ...next });
  // Each method reads its own kind of entry, so a list does not carry over.
  const selectMethod = (method: TunnelAuthMethod) => {
    if (method !== auth.method) {
      patch({ method, allow: [] });
    }
  };

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
    const index = METHODS.findIndex((method) => method.id === auth.method);
    const next = METHODS[(index + step + METHODS.length) % METHODS.length];
    if (next) {
      selectMethod(next.id);
      document.getElementById(`${groupId}-${next.id}`)?.focus();
    }
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
        {METHODS.map((method) => (
          <MethodCard
            key={method.id}
            method={method}
            domId={`${groupId}-${method.id}`}
            selected={method.id === auth.method}
            compact={compact}
            theme={theme}
            onSelect={() => selectMethod(method.id)}
            badge={
              method.id === "oidc" && !compact ? (
                <Badge theme={theme}>OpenID Connect</Badge>
              ) : null
            }
          />
        ))}
        <MethodCard
          method={EMAIL_METHOD}
          domId={`${groupId}-email`}
          selected={false}
          disabled
          compact={compact}
          theme={theme}
          badge={<Badge theme={theme}>Coming soon</Badge>}
        />
      </div>

      {auth.method === "none" ? (
        <p className={s.help}>
          Anyone who learns the address can open the app. Choose a sign-in
          method to limit it.
        </p>
      ) : (
        <div className={cn("space-y-4 rounded-lg border p-3", s.panel)}>
          <AllowList
            key={auth.method}
            auth={auth}
            patch={patch}
            issues={issues}
            theme={theme}
          />
          {auth.method === "oidc" && (
            <OIDCSetup
              auth={auth}
              patch={patch}
              issues={issues}
              currentOrigin={currentOrigin}
              name={name}
              os={os}
              theme={theme}
            />
          )}
          {auth.method === "credential" && (
            <InviteBlock
              allow={auth.allow}
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

function MethodCard<Id extends string>({
  method,
  domId,
  selected,
  disabled = false,
  compact,
  theme,
  badge,
  onSelect,
}: {
  method: MethodChoice<Id>;
  domId: string;
  selected: boolean;
  disabled?: boolean;
  compact: boolean;
  theme: TunnelFormTheme;
  badge?: ReactNode;
  onSelect?: () => void;
}) {
  const s = TUNNEL_FORM_STYLES[theme];
  const Icon = method.icon;
  return (
    <button
      id={domId}
      type="button"
      role="radio"
      aria-checked={selected}
      aria-disabled={disabled || undefined}
      tabIndex={selected ? 0 : -1}
      onClick={disabled ? undefined : onSelect}
      className={cn(
        "border text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        compact
          ? "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold"
          : "grid grid-cols-[auto_1fr] content-start gap-x-2.5 gap-y-0.5 rounded-lg px-3 py-2.5",
        s.card,
        selected && SELECTED,
        disabled && "cursor-not-allowed border-dashed opacity-60"
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
        {badge}
      </span>
      {!compact && (
        <span className={cn("col-start-2", s.help)}>{method.description}</span>
      )}
    </button>
  );
}

function Badge({
  theme,
  children,
}: {
  theme: TunnelFormTheme;
  children: ReactNode;
}) {
  return (
    <span
      className={cn(
        "rounded px-1.5 py-px text-[10px] font-semibold uppercase",
        theme === "terminal"
          ? "bg-white/10 text-slate-300"
          : "bg-secondary text-secondary-foreground dark:bg-primary/14 dark:text-primary"
      )}
    >
      {children}
    </span>
  );
}

function FieldIssues({
  issues,
  field,
  tone = "error",
  theme,
}: {
  issues: TunnelAuthIssue[];
  field: TunnelAuthField;
  tone?: "error" | "warn";
  theme: TunnelFormTheme;
}) {
  return issues
    .filter((issue) => issue.field === field)
    .map((issue) => (
      <Notice key={issue.message} tone={tone} theme={theme}>
        {issue.message}
      </Notice>
    ));
}

function AllowList({
  auth,
  patch,
  issues,
  theme,
}: {
  auth: TunnelAuthOptions;
  patch: (next: Partial<TunnelAuthOptions>) => void;
  issues: TunnelAuthIssue[];
  theme: TunnelFormTheme;
}) {
  const inputId = useId();
  const [draft, setDraft] = useState("");
  const s = TUNNEL_FORM_STYLES[theme];
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
        theme={theme}
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
              theme={theme}
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
            <Notice key={entry} tone="error" theme={theme}>
              {check.error}
            </Notice>
          )
        );
      })}
      <FieldIssues issues={issues} field="allow" theme={theme} />
      {auth.allow.length === 0 && method === "siwe" && (
        <Notice tone="warn" theme={theme}>
          No list: any wallet that signs in gets through. That proves a wallet
          exists, not who owns it.
        </Notice>
      )}
      {auth.allow.length === 0 && method === "credential" && (
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
  issues,
  currentOrigin,
  name,
  os,
  theme,
}: {
  auth: TunnelAuthOptions;
  patch: (next: Partial<TunnelAuthOptions>) => void;
  issues: TunnelAuthIssue[];
  currentOrigin: string;
  name: string;
  os: TunnelCommandOS;
  theme: TunnelFormTheme;
}) {
  const issuerId = useId();
  const clientId = useId();
  const s = TUNNEL_FORM_STYLES[theme];
  const isGoogle = auth.oidcIssuer === GOOGLE_OIDC_ISSUER;
  const redirectURL = buildAuthRedirectURL(currentOrigin, name);
  const inputClass = cn(s.input, "h-9 font-mono text-[13px] read-only:opacity-70");

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
                choice.active && SELECTED
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
          <Input
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
          <FieldIssues issues={issues} field="issuer" theme={theme} />
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
          <Input
            id={clientId}
            type="text"
            value={auth.oidcClientId}
            onChange={(event) => patch({ oidcClientId: event.target.value })}
            placeholder="abc.apps.googleusercontent.com"
            autoComplete="off"
            spellCheck={false}
            className={inputClass}
          />
          <FieldIssues issues={issues} field="clientId" theme={theme} />
        </div>
      </div>

      <div className="space-y-1.5">
        <p className={s.label}>1. At your provider</p>
        <p className={s.help}>
          Create an OAuth client for a web application and add this redirect
          address:
        </p>
        {redirectURL === "" ? (
          <FieldIssues issues={issues} field="name" tone="warn" theme={theme} />
        ) : (
          <CopyLine
            value={redirectURL}
            label="Copy redirect address"
            theme={theme}
          />
        )}
      </div>

      <div className="space-y-1.5">
        <p className={s.label}>2. In your terminal, before the command below</p>
        <p className={s.help}>
          Run this in the shell you will start the tunnel from. It asks for the
          client secret without showing it, so the secret stays out of the
          process list, your shell history and the command you copy.
          {os === "unix" && (
            <> If you press Ctrl-C at the prompt, run <code>stty echo</code> to
            see what you type again.</>
          )}
        </p>
        <CopyLine
          value={buildOIDCSecretCommand(os)}
          label="Copy secret prompt"
          theme={theme}
        />
      </div>
    </div>
  );
}

function InviteBlock({
  allow,
  currentOrigin,
  name,
  os,
  theme,
}: {
  allow: string[];
  currentOrigin: string;
  name: string;
  os: TunnelCommandOS;
  theme: TunnelFormTheme;
}) {
  const subjectId = useId();
  const expiresId = useId();
  const s = TUNNEL_FORM_STYLES[theme];
  const [subject, setSubject] = useState("");
  const [expires, setExpires] = useState("720h");
  const trimmed = subject.trim();
  const check = trimmed === "" ? null : classifyAuthAllow("credential", trimmed);
  // With names listed, the tunnel lets in only those subjects.
  const notListed = check?.ok && allow.length > 0 && !allow.includes(trimmed);
  const command = check?.ok
    ? buildAuthIssueCommand({
        origin: currentOrigin,
        name,
        subject: trimmed,
        expires,
        os,
      })
    : "";
  const hint =
    name === ""
      ? "Add a Name above, then a name for the person, to see the command."
      : check === null
        ? "Type the person's name to see the command."
        : "";
  const fieldClass = cn(s.input, "h-9 text-[13px]");

  return (
    <div className="space-y-2">
      <p className={s.label}>After it runs: invite someone</p>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5">
          <label htmlFor={subjectId} className={s.label}>
            Name
          </label>
          <Input
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
          <Select value={expires} onValueChange={setExpires}>
            <SelectTrigger id={expiresId} className={fieldClass}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {EXPIRY_CHOICES.map((choice) => (
                <SelectItem key={choice.value} value={choice.value}>
                  {choice.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      {check && !check.ok && (
        <Notice tone="error" theme={theme}>
          {check.error}
        </Notice>
      )}
      {notListed && (
        <Notice tone="warn" theme={theme}>
          {trimmed} is not in Link names, so the tunnel will not let that link
          in.
        </Notice>
      )}
      {command !== "" ? (
        <CopyLine value={command} label="Copy invite command" theme={theme} />
      ) : (
        hint !== "" && <p className={s.help}>{hint}</p>
      )}
      <p className={s.help}>
        Run it from the folder where you ran <code>portal expose</code>: both
        read <code>identity.json</code> from the current folder. It prints a
        link to send to that person. Anyone who holds the link gets in until
        it expires, so send it privately.
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
  auth: TunnelAuthOptions;
  currentOrigin: string;
  name: string;
  theme: TunnelFormTheme;
}) {
  const s = TUNNEL_FORM_STYLES[theme];
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
        <Badge theme={theme}>{hostname}</Badge>
        <p className={cn("mt-2 text-sm font-semibold", s.strong)}>
          {page.title}
        </p>
        <p className={cn("mx-auto mt-1 max-w-[36ch]", s.help)}>{page.body}</p>
        {page.action !== "" && (
          <span className="mt-3 inline-block rounded-md bg-primary px-4 py-1.5 text-xs font-bold text-primary-foreground">
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
  theme: TunnelFormTheme;
}) {
  const { copiedKey, copy } = useCopy();
  const s = TUNNEL_FORM_STYLES[theme];
  const copied = copiedKey !== null;

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
        onClick={() => copy(value)}
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
