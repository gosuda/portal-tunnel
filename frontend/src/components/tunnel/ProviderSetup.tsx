import {
  CopyLine,
  Hint,
  LABEL,
  RegisterNote,
  SecretPrompt,
  Segmented,
  TextField,
} from "./fields";
import {
  AUTH_CALLBACK_PATH,
  AUTH_SAML_ACS_PATH,
  AUTH_SAML_METADATA_PATH,
} from "@/lib/apiPaths";
import {
  GOOGLE_OIDC_ISSUER,
  buildAuthRedirectURLs,
  type TunnelAuthIssue,
  type TunnelAuthOptions,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

interface SetupProps {
  auth: TunnelAuthOptions;
  patch: (next: Partial<TunnelAuthOptions>) => void;
  issues: TunnelAuthIssue[];
}

interface HostProps {
  relayUrls: string[];
  discovery: boolean;
  name: string;
}

const PROVIDERS = [
  { id: "google", label: "Google" },
  { id: "other", label: "Another provider" },
] as const;

export function OIDCSetup({
  auth,
  patch,
  issues,
  relayUrls,
  discovery,
  name,
  os,
}: SetupProps & HostProps & { os: TunnelCommandOS }) {
  const isGoogle = auth.oidcIssuer === GOOGLE_OIDC_ISSUER;
  const redirectURLs = buildAuthRedirectURLs(relayUrls, name, AUTH_CALLBACK_PATH);

  return (
    <div className="space-y-4">
      <div className="space-y-1.5">
        <span className={LABEL}>Provider</span>
        <div>
          <Segmented
            label="Provider"
            options={PROVIDERS}
            value={isGoogle ? "google" : "other"}
            onChange={(provider) =>
              patch({
                oidcIssuer: provider === "google" ? GOOGLE_OIDC_ISSUER : "",
              })
            }
          />
        </div>
      </div>

      <TextField
        label="Issuer"
        value={auth.oidcIssuer}
        readOnly={isGoogle}
        onChange={(oidcIssuer) => patch({ oidcIssuer })}
        placeholder="https://login.example.com"
        issues={issues}
        field="issuer"
      >
        {!isGoogle && (
          <Hint>
            Any provider that publishes{" "}
            <code>/.well-known/openid-configuration</code>. GitHub does not:
            its login is not OpenID Connect.
          </Hint>
        )}
      </TextField>
      <TextField
        label="Client ID"
        value={auth.oidcClientId}
        onChange={(oidcClientId) => patch({ oidcClientId })}
        placeholder="abc.apps.googleusercontent.com"
        issues={issues}
        field="clientId"
      />

      <div className="space-y-1.5">
        <p className={LABEL}>1. At your provider</p>
        <Hint>
          Create an OAuth client for a web application. The provider sends
          visitors back only to the redirect addresses you register, so every
          address a visitor opens the app on needs its own.
        </Hint>
        {redirectURLs.map((url) => (
          <CopyLine
            key={url}
            value={url}
            label={`Copy redirect address ${url}`}
          />
        ))}
        <RegisterNote
          listed={redirectURLs.length > 0}
          name={name}
          discovery={discovery}
        >
          When the tunnel is ready, Portal prints each relay's address-bound
          URL after <code>service ready at</code>, and its short URL only if
          that relay granted the name. Register every address it prints that is
          not listed here, including the address-bound one: the address
          followed by <code>{AUTH_CALLBACK_PATH}</code>, without{" "}
          <code>:443</code>.
        </RegisterNote>
      </div>

      <SecretPrompt
        title="2. In your terminal, before the command below"
        secret="oidc"
        copyLabel="Copy secret prompt"
        os={os}
      />
    </div>
  );
}

export function SAMLSetup({
  auth,
  patch,
  issues,
  relayUrls,
  discovery,
  name,
}: SetupProps & HostProps) {
  const acsURLs = buildAuthRedirectURLs(relayUrls, name, AUTH_SAML_ACS_PATH);
  const metadataURLs = buildAuthRedirectURLs(relayUrls, name, AUTH_SAML_METADATA_PATH);

  return (
    <div className="space-y-4">
      <TextField
        label="Identity provider metadata"
        inputMode="url"
        value={auth.samlMetadataURL}
        onChange={(samlMetadataURL) => patch({ samlMetadataURL })}
        placeholder="https://idp.example.com/metadata"
        issues={issues}
        field="metadataURL"
      >
        <Hint>
          The address where the provider publishes its SAML metadata, such as
          Keycloak's <code>/protocol/saml/descriptor</code>. For a provider
          that only gives you a file, replace this flag with{" "}
          <code>--auth-saml-metadata-file</code> and the file's path.
        </Hint>
      </TextField>
      <div className="grid gap-3 sm:grid-cols-2">
        <TextField
          label="Entity ID"
          optional
          value={auth.samlEntityId}
          onChange={(samlEntityId) => patch({ samlEntityId })}
          placeholder="metadata address of each host"
        />
        <TextField
          label="Subject attribute"
          optional
          value={auth.samlSubjectAttribute}
          onChange={(samlSubjectAttribute) => patch({ samlSubjectAttribute })}
          placeholder="NameID"
        />
      </div>
      <Hint>
        The subject is the NameID unless you name an attribute, such as{" "}
        <code>email</code>. SAML does not say whether an email was verified, so
        Portal trusts the address the provider signs: let the provider send
        only addresses its users cannot change.
      </Hint>

      <div className="space-y-1.5">
        <p className={LABEL}>At your identity provider</p>
        <Hint>
          Add a SAML application. Import its metadata from the metadata
          address, or enter the ACS address with the HTTP-POST binding and the
          entity ID by hand. Have the provider sign the response or the
          assertion. Portal sends unsigned requests and does not accept
          encrypted assertions, and it accepts only sign-ins that start at the
          app, not at the provider's app list.
        </Hint>
        {acsURLs.map((url) => (
          <CopyLine key={url} value={url} label={`Copy ACS address ${url}`} />
        ))}
        {metadataURLs.map((url) => (
          <CopyLine
            key={url}
            value={url}
            label={`Copy metadata address ${url}`}
          />
        ))}
        <RegisterNote
          listed={acsURLs.length > 0}
          name={name}
          discovery={discovery}
        >
          Every address a visitor opens the app on has its own ACS address:
          the address followed by <code>{AUTH_SAML_ACS_PATH}</code>, without{" "}
          <code>:443</code>. When the tunnel is ready, Portal prints each
          relay's address-bound URL after <code>service ready at</code>. With
          more than one address, set an Entity ID so the provider sees one
          application, and register every ACS address with it.
        </RegisterNote>
      </div>
    </div>
  );
}

export function EmailSetup({
  auth,
  patch,
  issues,
  os,
}: SetupProps & { os: TunnelCommandOS }) {
  return (
    <div className="space-y-4">
      <TextField
        label="SMTP server"
        value={auth.emailSMTPAddr}
        onChange={(emailSMTPAddr) => patch({ emailSMTPAddr })}
        placeholder="smtp.example.com:587"
        issues={issues}
        field="smtpAddr"
      >
        <Hint>
          The host and port of your mail provider's submission server, such as
          a mailbox with an app password or a transactional mail service. Port
          465 starts with TLS. Any other port must offer STARTTLS, and only a
          server on this computer at localhost, 127.0.0.1 or ::1 may run
          without TLS.
        </Hint>
      </TextField>
      <TextField
        label="Sender"
        value={auth.emailFrom}
        onChange={(emailFrom) => patch({ emailFrom })}
        placeholder="Portal <login@example.com>"
        issues={issues}
        field="from"
      >
        <Hint>
          Every link comes from this one address. Use an address your SMTP
          account may send from.
        </Hint>
      </TextField>
      <TextField
        label="SMTP username"
        optional
        value={auth.emailSMTPUsername}
        onChange={(emailSMTPUsername) => patch({ emailSMTPUsername })}
        placeholder="login@example.com"
      >
        <Hint>Leave it empty only for a server that needs no login.</Hint>
      </TextField>

      {auth.emailSMTPUsername.trim() !== "" && (
        <SecretPrompt
          title="In your terminal, before the command below"
          secret="email"
          copyLabel="Copy password prompt"
          os={os}
        />
      )}

      <Hint>
        The sign-in page answers every well-formed address the same way, so it
        does not show who is on the list. One address gets at most one link per
        minute and five per hour. The addresses that only an @domain entry
        allows share fifty links per hour across all @domain entries, so
        made-up addresses can use that budget up while the flood lasts and for
        up to an hour after; list addresses exactly where that matters. A link
        works once, for 10 minutes; restarting the tunnel cancels the links not
        used yet. A visitor is not told when a mail fails: a failed send shows
        in the tunnel log, and a refusal by a limit or by the list logs
        nothing.
      </Hint>
    </div>
  );
}
