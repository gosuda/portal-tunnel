import {
  CopyLine,
  PROVIDERS,
  RegisterNote,
  SecretPrompt,
  SELECTED,
  TextField,
  useRadioGroup,
} from "./authShared";
import { TUNNEL_FORM_STYLES as s } from "@/components/TunnelFormParts";
import { AUTH_CALLBACK_PATH } from "@/lib/apiPaths";
import { cn } from "@/lib/utils";
import {
  GOOGLE_OIDC_ISSUER,
  buildAuthRedirectURLs,
  type TunnelAuthIssue,
  type TunnelAuthOptions,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

export function OIDCSetup({
  auth,
  patch,
  issues,
  relayUrls,
  discovery,
  name,
  os,
}: {
  auth: TunnelAuthOptions;
  patch: (next: Partial<TunnelAuthOptions>) => void;
  issues: TunnelAuthIssue[];
  relayUrls: string[];
  discovery: boolean;
  name: string;
  os: TunnelCommandOS;
}) {
  const isGoogle = auth.oidcIssuer === GOOGLE_OIDC_ISSUER;
  const providers = useRadioGroup(
    PROVIDERS.map((provider) => provider.id),
    isGoogle ? "google" : "other",
    (provider) =>
      patch({ oidcIssuer: provider === "google" ? GOOGLE_OIDC_ISSUER : "" })
  );
  const redirectURLs = buildAuthRedirectURLs(relayUrls, name, AUTH_CALLBACK_PATH);

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
            <p className={s.help}>
              Any provider that publishes{" "}
              <code>/.well-known/openid-configuration</code>. GitHub does not:
              its login is not OpenID Connect.
            </p>
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
      </div>

      <div className="space-y-1.5">
        <p className={s.label}>1. At your provider</p>
        <p className={s.help}>
          Create an OAuth client for a web application. The provider sends
          visitors back only to the redirect addresses you register, so every
          address a visitor opens the app on needs its own.
        </p>
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
        noun="client secret"
        shortNoun="secret"
        copyLabel="Copy secret prompt"
        os={os}
      />
    </div>
  );
}
