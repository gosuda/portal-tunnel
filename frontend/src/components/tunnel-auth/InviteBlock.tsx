import { useId, useState } from "react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Notice, TUNNEL_FORM_STYLES as s } from "@/components/TunnelFormParts";
import { CopyLine, EXPIRY_CHOICES, TextField } from "./authShared";
import { cn } from "@/lib/utils";
import {
  applicationAuthHost,
  buildAuthIssueCommand,
  classifyAuthAllow,
  isListedSubject,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

export function InviteBlock({
  allow,
  exampleURL,
  os,
}: {
  allow: string[];
  /** The short URL on the first relay, shown as the placeholder; may be empty. */
  exampleURL: string;
  os: TunnelCommandOS;
}) {
  const expiresId = useId();
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

  return (
    <div className="space-y-2">
      <p className={s.label}>After it runs: invite someone</p>
      <TextField
        label="URL you send"
        inputMode="url"
        value={address}
        onChange={setAddress}
        placeholder={exampleURL || "https://"}
      >
        {badAddress && (
          <Notice tone="error">
            Paste an https:// address without a path, as Portal prints it.
          </Notice>
        )}
        <p className={s.help}>
          A link works only on the address it was made for. Paste the URL
          Portal printed for the relay you share: the short URL if it printed
          one, otherwise the address after <code>service ready at</code>.
        </p>
      </TextField>
      <div className="grid gap-3 sm:grid-cols-2">
        <TextField
          label="Name"
          value={subject}
          onChange={setSubject}
          placeholder="alice"
        />
        <div className="space-y-1.5">
          <label htmlFor={expiresId} className={s.label}>
            Valid for
          </label>
          <Select value={expires} onValueChange={setExpires}>
            <SelectTrigger id={expiresId} className={cn(s.input, "h-9 text-[13px]")}>
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
        <Notice tone="error">
          {check.error}
        </Notice>
      )}
      {notListed && (
        <Notice tone="warn">
          {trimmed} is not in Link names, so the tunnel will not let that link
          in.
        </Notice>
      )}
      {command !== "" ? (
        <CopyLine value={command} label="Copy invite command" />
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
