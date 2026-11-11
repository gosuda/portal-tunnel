import type { JSX } from "react";
import { SecretPrompt, TextField } from "./authShared";
import { TUNNEL_FORM_STYLES as s } from "@/components/TunnelFormParts";
import type {
  TunnelAuthIssue,
  TunnelAuthOptions,
  TunnelCommandOS,
} from "@/lib/tunnelCommand";

export function EmailSetup({
  auth,
  patch,
  issues,
  os,
}: {
  auth: TunnelAuthOptions;
  patch: (next: Partial<TunnelAuthOptions>) => void;
  issues: TunnelAuthIssue[];
  os: TunnelCommandOS;
}): JSX.Element {

  return (
    <div className="space-y-4">
      <div className="space-y-3">
        <TextField
          label="SMTP server"
          value={auth.emailSMTPAddr}
          onChange={(emailSMTPAddr) => patch({ emailSMTPAddr })}
          placeholder="smtp.example.com:587"
          issues={issues}
          field="smtpAddr"
        >
          <p className={s.help}>
            The host and port of your mail provider's submission server, such
            as a mailbox with an app password or a transactional mail service.
            Port 465 starts with TLS. Any other port must offer STARTTLS, and
            only a server on this computer at localhost, 127.0.0.1 or ::1 may
            run without TLS.
          </p>
        </TextField>
        <TextField
          label="Sender"
          value={auth.emailFrom}
          onChange={(emailFrom) => patch({ emailFrom })}
          placeholder="Portal <login@example.com>"
          issues={issues}
          field="from"
        >
          <p className={s.help}>
            Every link comes from this one address. Use an address your SMTP
            account may send from.
          </p>
        </TextField>
        <TextField
          label="SMTP username"
          optional
          value={auth.emailSMTPUsername}
          onChange={(emailSMTPUsername) => patch({ emailSMTPUsername })}
          placeholder="login@example.com"
        >
          <p className={s.help}>
            Leave it empty only for a server that needs no login.
          </p>
        </TextField>
      </div>

      {auth.emailSMTPUsername.trim() !== "" && (
        <SecretPrompt
          title="In your terminal, before the command below"
          secret="email"
          noun="SMTP password"
          shortNoun="password"
          copyLabel="Copy password prompt"
          os={os}
        />
      )}

      <p className={s.help}>
        The sign-in page answers every well-formed address the same way, so it
        does not show who is on the list. One address gets at most one link per
        minute and five per hour. The addresses that only an @domain entry
        allows share fifty links per hour across all @domain entries, so
        made-up addresses can use that budget up while the flood lasts and for
        up to an hour after; list addresses exactly where that matters. A link
        works once, for 10 minutes; restarting the tunnel cancels the links
        not used yet. A visitor is not told when a mail fails: a failed send
        shows in the tunnel log, and a refusal by a limit or by the list logs
        nothing.
      </p>
    </div>
  );
}
