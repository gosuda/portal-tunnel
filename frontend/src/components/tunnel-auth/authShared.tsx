import { useId, type KeyboardEvent, type ReactNode } from "react";
import {
  Building2,
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
import { Notice, TUNNEL_FORM_STYLES as s } from "@/components/TunnelFormParts";
import { useCopy } from "@/hooks/useCopy";
import { cn } from "@/lib/utils";
import {
  buildSecretCommand,
  type TunnelAuthField,
  type TunnelAuthIssue,
  type TunnelAuthMethod,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

export interface MethodChoice {
  id: TunnelAuthMethod;
  label: string;
  icon: LucideIcon;
}

export const METHODS: MethodChoice[] = [
  {
    id: "none",
    label: "No sign-in",
    icon: Globe,
  },
  {
    id: "credential",
    label: "Private link",
    icon: Link2,
  },
  {
    id: "siwe",
    label: "Ethereum wallet",
    icon: Wallet,
  },
  {
    id: "oidc",
    label: "Google or company login",
    icon: ShieldCheck,
  },
  {
    id: "saml",
    label: "Company single sign-on",
    icon: Building2,
  },
  {
    id: "email",
    label: "Email link",
    icon: Mail,
  },
];

export const EXPIRY_CHOICES = [
  { value: "24h", label: "1 day" },
  { value: "168h", label: "7 days" },
  { value: "720h", label: "30 days" },
  { value: "2160h", label: "90 days" },
];

export const SELECTED = "border-primary bg-primary/10 ring-1 ring-primary";

export const PROVIDERS = [
  { id: "google", label: "Google" },
  { id: "other", label: "Another provider" },
] as const;

export const ALLOW_COPY: Record<
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

export interface RadioOptionProps {
  id: string;
  role: "radio";
  "aria-checked": boolean;
  tabIndex: number;
  onClick: () => void;
}

export function useRadioGroup<Id extends string>(
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
    let step = 0;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      step = 1;
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      step = -1;
    } else {
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

export function MethodCard({
  method,
  radio,
}: {
  method: MethodChoice;
  radio: RadioOptionProps;
}) {
  const Icon = method.icon;
  const selected = radio["aria-checked"];
  return (
    <button
      type="button"
      {...radio}
      className={cn(
        "border text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        "flex items-center gap-2.5 rounded-lg px-3 py-2.5",
        s.card,
        selected && SELECTED
      )}
    >
      <Icon
        aria-hidden="true"
        className={cn(
          "h-4 w-4 shrink-0",
          selected && "text-primary"
        )}
      />
      <span className="flex flex-wrap items-center gap-1.5 text-[13px] font-semibold">
        {method.label}
      </span>
    </button>
  );
}

export function Badge({ children }: { children: ReactNode }) {
  return (
    <span
      className="rounded bg-secondary px-1.5 py-px text-[10px] font-semibold uppercase text-secondary-foreground dark:bg-primary/14 dark:text-primary"
    >
      {children}
    </span>
  );
}

export function FieldIssues({
  issues,
  field,
}: {
  issues: TunnelAuthIssue[];
  field: TunnelAuthField;
}) {
  return issues
    .filter((issue) => issue.field === field)
    .map((issue) => (
      <Notice key={issue.message} tone="error">
        {issue.message}
      </Notice>
    ));
}

export function CopyLine({
  value,
  label,
}: {
  value: string;
  label: string;
}) {
  const { copiedKey, copy } = useCopy();
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

const FIELD_INPUT_CLASS = cn(
  s.input,
  "h-9 font-mono text-[13px] read-only:opacity-70"
);

export function TextField({
  label,
  optional = false,
  value,
  onChange,
  placeholder,
  issues,
  field,
  inputMode,
  readOnly,
  children,
}: {
  label: string;
  optional?: boolean;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  issues?: TunnelAuthIssue[];
  field?: TunnelAuthField;
  inputMode?: "url";
  readOnly?: boolean;
  children?: ReactNode;
}) {
  const id = useId();
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className={s.label}>
        {label}
        {optional && (
          <>
            {" "}
            <span className="font-normal opacity-70">(optional)</span>
          </>
        )}
      </label>
      <Input
        id={id}
        type="text"
        inputMode={inputMode}
        value={value}
        readOnly={readOnly}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        autoComplete="off"
        spellCheck={false}
        className={FIELD_INPUT_CLASS}
      />
      {issues && field && <FieldIssues issues={issues} field={field} />}
      {children}
    </div>
  );
}

export function SecretPrompt({
  title,
  secret,
  noun,
  shortNoun,
  copyLabel,
  os,
}: {
  title: string;
  secret: "oidc" | "email";
  noun: string;
  shortNoun: string;
  copyLabel: string;
  os: TunnelCommandOS;
}) {
  return (
    <div className="space-y-1.5">
      <p className={s.label}>{title}</p>
      <p className={s.help}>
        Run this in the shell you will start the tunnel from. It asks for the{" "}
        {noun} without showing it, so the {shortNoun} stays out of the process
        list, your shell history and the command you copy.
        {os === "unix" && (
          <> If you press Ctrl-C at the prompt, run <code>stty echo</code> to
          see what you type again.</>
        )}
      </p>
      <CopyLine value={buildSecretCommand(secret, os)} label={copyLabel} />
    </div>
  );
}

export function RegisterNote({
  listed,
  name,
  discovery,
  children,
}: {
  listed: boolean;
  name: string;
  discovery: boolean;
  children: ReactNode;
}) {
  return (
    <p className={s.help}>
      {listed
        ? "These are for the short URL on each relay in the command. "
        : name === "" &&
          "A Name gives each relay a short URL you can register now. "}
      {children}
      {discovery && (
        <>
          {" "}Relay discovery, on by default, can publish on more relays,
          each with its own addresses; to keep to the relays in the command,
          add <code>--discovery=false</code>.
        </>
      )}
    </p>
  );
}
