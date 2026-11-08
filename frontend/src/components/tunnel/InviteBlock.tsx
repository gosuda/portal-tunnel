import { useId, useState } from "react";
import { Select } from "@/components/ui/input";
import { CopyLine, Hint, LABEL, Notice, TextField } from "./fields";
import {
  applicationAuthHost,
  buildAuthIssueCommand,
  classifyAuthAllow,
  isListedSubject,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

const EXPIRY_CHOICES = [
  { value: "24h", label: "1 day" },
  { value: "168h", label: "7 days" },
  { value: "720h", label: "30 days" },
  { value: "2160h", label: "90 days" },
];

export function InviteBlock({
  allow,
  exampleURL,
  os,
}: {
  allow: string[];
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
    <div className="space-y-3">
      <p className={LABEL}>After it runs: invite someone</p>
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
        <Hint>
          A link works only on the address it was made for. Paste the URL
          Portal printed for the relay you share: the short URL if it printed
          one, otherwise the address after <code>service ready at</code>.
        </Hint>
      </TextField>
      <div className="grid gap-3 sm:grid-cols-2">
        <TextField
          label="Name"
          value={subject}
          onChange={setSubject}
          placeholder="alice"
        />
        <div className="space-y-1.5">
          <label htmlFor={expiresId} className={LABEL}>
            Valid for
          </label>
          <Select
            id={expiresId}
            value={expires}
            onChange={(event) => setExpires(event.target.value)}
          >
            {EXPIRY_CHOICES.map((choice) => (
              <option key={choice.value} value={choice.value}>
                {choice.label}
              </option>
            ))}
          </Select>
        </div>
      </div>
      {check && !check.ok && <Notice tone="error">{check.error}</Notice>}
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
          <Hint>
            Fill in the URL you send and the person's name to see the command.
          </Hint>
        )
      )}
      <Hint>
        Run it from the folder where you ran <code>portal expose</code>: both
        read <code>identity.json</code> from the current folder. It prints a
        link to send to that person. Anyone who holds the link gets in until
        it expires, so send it privately.
      </Hint>
    </div>
  );
}
