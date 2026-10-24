import { useId, useState, type KeyboardEvent, type ReactNode } from "react";
import {
  Check,
  Copy,
  Globe,
  Link2,
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
  applicationAuthHost,
  buildAuthIssueCommand,
  buildAuthRedirectURLs,
  buildOIDCSecretCommand,
  buildServiceStatusHostname,
  buildTunnelPreviewURL,
  classifyAuthAllow,
  isListedSubject,
  type TunnelAuthField,
  type TunnelAuthIssue,
  type TunnelAuthMethod,
  type TunnelAuthOptions,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

interface MethodChoice {
  id: TunnelAuthMethod;
  label: string;
  short: string;
  description: string;
  icon: LucideIcon;
}

const METHODS: MethodChoice[] = [
  {
    id: "none",
    label: "No sign-in",
    short: "No sign-in",
    description: "Anyone who discovers the public address can open the app.",
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

const EXPIRY_CHOICES = [
  { value: "24h", label: "1 day" },
  { value: "168h", label: "7 days" },
  { value: "720h", label: "30 days" },
  { value: "2160h", label: "90 days" },
];

const SELECTED = "border-primary bg-primary/10 ring-1 ring-primary";

const PROVIDERS = [
  { id: "google", label: "Google" },
  { id: "other", label: "Another provider" },
] as const;

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
  /** The relays in the command; each gives the app its own host. */
  relayUrls: string[];
  /** Whether relay discovery may publish the app on more relays. */
  discovery: boolean;
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
  relayUrls,
  discovery,
  name,
  os,
  theme,
  compact = false,
}: TunnelAuthSectionProps) {
  const s = TUNNEL_FORM_STYLES[theme];
  const patch = (next: Partial<TunnelAuthOptions>) =>
    onChange({ ...auth, ...next });
  // Each method reads its own kind of entry, so a list does not carry over.
  const methods = useRadioGroup(
    METHODS.map((method) => method.id),
    auth.method,
    (method) => patch({ method, allow: [] })
  );

  return (
    <div className="space-y-3">
      <div
        role="radiogroup"
        aria-label="Who can open it"
        onKeyDown={methods.onKeyDown}
        className={cn(
          compact ? "flex flex-wrap gap-1.5" : "grid gap-2 sm:grid-cols-2"
        )}
      >
        {METHODS.map((method) => (
          <MethodCard
            key={method.id}
            method={method}
            radio={methods.option(method.id)}
            compact={compact}
            theme={theme}
            badge={
              method.id === "oidc" && !compact ? (
                <Badge theme={theme}>OpenID Connect</Badge>
              ) : null
            }
          />
        ))}
      </div>

      {auth.method === "none" ? (
        <p className={s.help}>
          Anyone who discovers the public address can open the app. Choose a
          sign-in method to limit it.
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
              relayUrls={relayUrls}
              discovery={discovery}
              name={name}
              os={os}
              theme={theme}
            />
          )}
          {auth.method === "credential" && (
            <InviteBlock
              allow={auth.allow}
              exampleURL={buildTunnelPreviewURL(relayUrls[0] ?? "", name)}
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
          relayURL={relayUrls[0] ?? ""}
          name={name}
          theme={theme}
        />
      )}
    </div>
  );
}

interface RadioOptionProps {
  id: string;
  role: "radio";
  "aria-checked": boolean;
  tabIndex: number;
  onClick: () => void;
}

/**
 * A radio group made of buttons: only the checked option is in the tab
 * order, and the arrow keys move to the next option and check it.
 */
function useRadioGroup<Id extends string>(
  ids: readonly Id[],
  value: Id,
  onChange: (id: Id) => void
) {
  const groupId = useId();
  const optionId = (id: Id) => `${groupId}-${id}`;
  const select = (id: Id) => {
    if (id !== value) {
      onChange(id);
    }
  };
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
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
    const next = ids[(ids.indexOf(value) + step + ids.length) % ids.length];
    if (next !== undefined) {
      select(next);
      document.getElementById(optionId(next))?.focus();
    }
  };
  const option = (id: Id): RadioOptionProps => ({
    id: optionId(id),
    role: "radio",
    "aria-checked": id === value,
    tabIndex: id === value ? 0 : -1,
    onClick: () => select(id),
  });
  return { onKeyDown, option };
}

function MethodCard({
  method,
  radio,
  compact,
  theme,
  badge,
}: {
  method: MethodChoice;
  radio: RadioOptionProps;
  compact: boolean;
  theme: TunnelFormTheme;
  badge?: ReactNode;
}) {
  const s = TUNNEL_FORM_STYLES[theme];
  const Icon = method.icon;
  const selected = radio["aria-checked"];
  return (
    <button
      type="button"
      {...radio}
      className={cn(
        "border text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        compact
          ? "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold"
          : "grid grid-cols-[auto_1fr] content-start gap-x-2.5 gap-y-0.5 rounded-lg px-3 py-2.5",
        s.card,
        selected && SELECTED
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
      {/* Always mounted: a live region announces text that appears inside it. */}
      <div role="status">
        {auth.allow.length === 0 && method === "siwe" && (
          <Notice tone="warn" theme={theme}>
            The list is empty, so any wallet that signs in gets through, which
            proves a wallet exists, not who owns it. Removing the last address
            does not end its access: stop the tunnel instead (or list a
            placeholder address nobody will use).
          </Notice>
        )}
        {auth.allow.length === 0 && method === "credential" && (
          <Notice tone="warn" theme={theme}>
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

function OIDCSetup({
  auth,
  patch,
  issues,
  relayUrls,
  discovery,
  name,
  os,
  theme,
}: {
  auth: TunnelAuthOptions;
  patch: (next: Partial<TunnelAuthOptions>) => void;
  issues: TunnelAuthIssue[];
  relayUrls: string[];
  discovery: boolean;
  name: string;
  os: TunnelCommandOS;
  theme: TunnelFormTheme;
}) {
  const issuerId = useId();
  const clientId = useId();
  const s = TUNNEL_FORM_STYLES[theme];
  const isGoogle = auth.oidcIssuer === GOOGLE_OIDC_ISSUER;
  const providers = useRadioGroup(
    PROVIDERS.map((provider) => provider.id),
    isGoogle ? "google" : "other",
    (provider) =>
      patch({ oidcIssuer: provider === "google" ? GOOGLE_OIDC_ISSUER : "" })
  );
  const redirectURLs = buildAuthRedirectURLs(relayUrls, name);
  const inputClass = cn(s.input, "h-9 font-mono text-[13px] read-only:opacity-70");

  return (
    <div className="space-y-4">
      <div className="space-y-1.5">
        <span className={s.label}>Provider</span>
        <div
          className="flex gap-1.5"
          role="radiogroup"
          aria-label="Provider"
          onKeyDown={providers.onKeyDown}
        >
          {PROVIDERS.map((provider) => {
            const radio = providers.option(provider.id);
            return (
              <button
                key={provider.id}
                type="button"
                {...radio}
                className={cn(
                  "rounded-full border px-3 py-1 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  s.card,
                  radio["aria-checked"] && SELECTED
                )}
              >
                {provider.label}
              </button>
            );
          })}
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
          Create an OAuth client for a web application. The provider sends
          visitors back only to the redirect addresses you register, so every
          address a visitor opens the app on needs its own.
        </p>
        {name === "" ? (
          <FieldIssues issues={issues} field="name" tone="warn" theme={theme} />
        ) : (
          <>
            {redirectURLs.map((url) => (
              <CopyLine
                key={url}
                value={url}
                label={`Copy redirect address ${url}`}
                theme={theme}
              />
            ))}
            <p className={s.help}>
              {redirectURLs.length > 0 &&
                "These are for the short URL on each relay in the command. "}
              When the tunnel is ready, Portal prints each relay's
              address-bound URL after <code>service ready at</code>, and its
              short URL only if that relay granted the name. Register the
              address-bound URL as well, and any short URL not listed here: the
              address followed by <code>/_portal/auth/callback</code>, without{" "}
              <code>:443</code>.
              {discovery && (
                <>
                  {" "}Relay discovery, on by default, can publish on more
                  relays, each with its own addresses; to keep to the relays in
                  the command, add <code>--discovery=false</code>.
                </>
              )}
            </p>
          </>
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
  exampleURL,
  os,
  theme,
}: {
  allow: string[];
  /** The short URL on the first relay, shown as the placeholder; may be empty. */
  exampleURL: string;
  os: TunnelCommandOS;
  theme: TunnelFormTheme;
}) {
  const addressId = useId();
  const subjectId = useId();
  const expiresId = useId();
  const s = TUNNEL_FORM_STYLES[theme];
  const [address, setAddress] = useState("");
  const [subject, setSubject] = useState("");
  const [expires, setExpires] = useState("720h");
  const trimmed = subject.trim();
  const check = trimmed === "" ? null : classifyAuthAllow("credential", trimmed);
  const notListed = check?.ok && !isListedSubject(allow, trimmed);
  const badAddress = address.trim() !== "" && applicationAuthHost(address) === "";
  const command = check?.ok
    ? buildAuthIssueCommand({ address, subject: trimmed, expires, os })
    : "";
  const missing = address.trim() === "" || check === null;
  const fieldClass = cn(s.input, "h-9 text-[13px]");

  return (
    <div className="space-y-2">
      <p className={s.label}>After it runs: invite someone</p>
      <div className="space-y-1.5">
        <label htmlFor={addressId} className={s.label}>
          URL you send
        </label>
        <Input
          id={addressId}
          type="text"
          inputMode="url"
          value={address}
          onChange={(event) => setAddress(event.target.value)}
          placeholder={exampleURL || "https://"}
          autoComplete="off"
          spellCheck={false}
          className={cn(fieldClass, "font-mono")}
        />
        {badAddress && (
          <Notice tone="error" theme={theme}>
            Paste an https:// address without a path, as Portal prints it.
          </Notice>
        )}
        <p className={s.help}>
          A link works only on the address it was made for. Paste the URL
          Portal printed for the relay you share: the short URL if it printed
          one, otherwise the address after <code>service ready at</code>.
        </p>
      </div>
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
        missing && (
          <p className={s.help}>
            Fill in the URL you send and the person's name to see the command.
          </p>
        )
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
  relayURL,
  name,
  theme,
}: {
  auth: TunnelAuthOptions;
  relayURL: string;
  name: string;
  theme: TunnelFormTheme;
}) {
  const s = TUNNEL_FORM_STYLES[theme];
  const hostname =
    buildServiceStatusHostname(relayURL, name) || "your-name.relay";
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
