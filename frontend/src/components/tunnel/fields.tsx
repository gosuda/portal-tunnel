import { useId, type ReactNode } from "react";
import { Check, Copy, TriangleAlert, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { useCopy } from "@/hooks/useCopy";
import { cn } from "@/lib/utils";
import {
  buildSecretCommand,
  type TunnelAuthField,
  type TunnelAuthIssue,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

export const LABEL = "text-xs font-semibold text-content-emphasis";

export function Hint({ children }: { children: ReactNode }) {
  return <p className="text-xs leading-5 text-content-muted">{children}</p>;
}

export function Notice({
  tone,
  children,
}: {
  tone: "error" | "warn";
  children: ReactNode;
}) {
  return (
    <p
      className={cn(
        "flex items-start gap-1.5 text-xs leading-5",
        tone === "error" ? "text-danger" : "text-warning"
      )}
    >
      <TriangleAlert aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
      <span>{children}</span>
    </p>
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

export function Segmented<Id extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: readonly { id: Id; label: string }[];
  value: Id;
  onChange: (id: Id) => void;
}) {
  const name = useId();
  return (
    <div
      role="radiogroup"
      aria-label={label}
      className="inline-flex gap-1 rounded-md bg-surface-200 p-1"
    >
      {options.map((option) => (
        <label
          key={option.id}
          className="interactive flex h-8 cursor-pointer items-center rounded-sm px-3 text-sm font-semibold text-content-muted has-checked:bg-surface-300 has-checked:text-content-emphasis has-focus-visible:outline-3 has-focus-visible:outline-focus"
        >
          <input
            type="radio"
            name={name}
            className="sr-only"
            checked={option.id === value}
            onChange={() => onChange(option.id)}
          />
          {option.label}
        </label>
      ))}
    </div>
  );
}

interface ChipItem {
  text: string;
  kind?: string;
  invalid?: boolean;
  removeLabel: string;
  removeDisabled?: boolean;
  onRemove: () => void;
}

export function ChipInput({
  id,
  chips,
  draft,
  placeholder,
  commitKeys = ["Enter"],
  commitOnBlur = false,
  onDraftChange,
  onCommit,
  onRemoveLast,
}: {
  id?: string;
  chips: ChipItem[];
  draft: string;
  placeholder: string;
  commitKeys?: string[];
  commitOnBlur?: boolean;
  onDraftChange: (draft: string) => void;
  onCommit: () => void;
  onRemoveLast: () => void;
}) {
  return (
    <div className="flex min-h-10 flex-wrap items-center gap-1.5 rounded-md border border-stroke bg-surface-100 p-1.5 focus-within:border-primary">
      {chips.map((chip) => (
        <span
          key={chip.text}
          className={cn(
            "inline-flex min-h-7 items-center gap-1 rounded-sm bg-surface-300 pl-2 text-xs font-semibold text-content-emphasis",
            chip.invalid && "outline-1 outline-danger"
          )}
        >
          {chip.kind && (
            <span
              className={cn(
                "text-[10px] font-semibold uppercase",
                chip.invalid ? "text-danger" : "text-content-muted"
              )}
            >
              {chip.kind}
            </span>
          )}
          <span className="break-all">{chip.text}</span>
          <button
            type="button"
            onClick={chip.onRemove}
            aria-label={chip.removeLabel}
            disabled={chip.removeDisabled}
            className="interactive grid size-7 place-items-center rounded-sm disabled:cursor-not-allowed disabled:opacity-40"
          >
            <X className="size-3" />
          </button>
        </span>
      ))}
      <input
        id={id}
        type="text"
        value={draft}
        onChange={(event) => onDraftChange(event.target.value)}
        onKeyDown={(event) => {
          if (commitKeys.includes(event.key)) {
            event.preventDefault();
            onCommit();
          } else if (event.key === "Backspace" && draft === "") {
            onRemoveLast();
          }
        }}
        onBlur={commitOnBlur ? onCommit : undefined}
        placeholder={placeholder}
        autoComplete="off"
        spellCheck={false}
        className="h-7 min-w-36 flex-1 bg-transparent px-1 text-sm text-content-emphasis outline-none placeholder:text-content-muted"
      />
    </div>
  );
}

export function CopyLine({ value, label }: { value: string; label: string }) {
  const { copiedKey, copy } = useCopy();
  const copied = copiedKey !== null;

  return (
    <div className="flex items-center gap-1 rounded-md bg-surface-200 py-1 pl-3 pr-1 font-mono text-xs">
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap py-1 no-scrollbar">
        {value}
      </code>
      <button
        type="button"
        onClick={() => copy(value)}
        aria-label={label}
        title={copied ? "Copied" : "Copy"}
        className="interactive grid size-10 shrink-0 place-items-center rounded-md"
      >
        {copied ? (
          <Check className="size-4 text-success" />
        ) : (
          <Copy className="size-4" />
        )}
      </button>
    </div>
  );
}

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
      <label htmlFor={id} className={cn(LABEL, "block")}>
        {label}
        {optional && (
          <>
            {" "}
            <span className="font-normal text-content-muted">(optional)</span>
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
        className="font-mono text-[13px] read-only:opacity-70"
      />
      {issues && field && <FieldIssues issues={issues} field={field} />}
      {children}
    </div>
  );
}

const SECRET_NAMES = {
  oidc: { full: "client secret", short: "secret" },
  email: { full: "SMTP password", short: "password" },
} as const;

export function SecretPrompt({
  title,
  secret,
  copyLabel,
  os,
}: {
  title: string;
  secret: keyof typeof SECRET_NAMES;
  copyLabel: string;
  os: TunnelCommandOS;
}) {
  const { full, short } = SECRET_NAMES[secret];
  return (
    <div className="space-y-1.5">
      <p className={LABEL}>{title}</p>
      <Hint>
        Run this in the shell you will start the tunnel from. It asks for the{" "}
        {full} without showing it, so the {short} stays out of the process
        list, your shell history and the command you copy.
        {os === "unix" && (
          <> If you press Ctrl-C at the prompt, run <code>stty echo</code> to
          see what you type again.</>
        )}
      </Hint>
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
    <Hint>
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
    </Hint>
  );
}
