import { TUNNEL_FORM_STYLES as s } from "@/components/TunnelFormParts";
import { cn } from "@/lib/utils";
import {
  buildTunnelPreviewURL,
  type TunnelAuthIssue,
  type TunnelAuthOptions,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";
import {
  METHODS,
  MethodCard,
  useRadioGroup,
} from "./tunnel-auth/authShared";
import { AllowList } from "./tunnel-auth/AllowList";
import { OIDCSetup } from "./tunnel-auth/OIDCSetup";
import { SAMLSetup } from "./tunnel-auth/SAMLSetup";
import { EmailSetup } from "./tunnel-auth/EmailSetup";
import { InviteBlock } from "./tunnel-auth/InviteBlock";
import { VisitorPreview } from "./tunnel-auth/VisitorPreview";

export interface TunnelAuthSectionProps {
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
}

export function TunnelAuthSection({
  auth,
  onChange,
  issues,
  relayUrls,
  discovery,
  name,
  os,
}: TunnelAuthSectionProps) {
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
        className="grid gap-2 sm:grid-cols-2"
      >
        {METHODS.map((method) => (
          <MethodCard
            key={method.id}
            method={method}
            radio={methods.option(method.id)}
          />
        ))}
      </div>

      {auth.method !== "none" && (
        <div className={cn("space-y-4 rounded-lg border p-3", s.panel)}>
          <AllowList
            key={auth.method}
            auth={auth}
            patch={patch}
            issues={issues}
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
            />
          )}
          {auth.method === "saml" && (
            <SAMLSetup
              auth={auth}
              patch={patch}
              issues={issues}
              relayUrls={relayUrls}
              discovery={discovery}
              name={name}
            />
          )}
          {auth.method === "email" && (
            <EmailSetup auth={auth} patch={patch} issues={issues} os={os} />
          )}
          {auth.method === "credential" && (
            <InviteBlock
              allow={auth.allow}
              exampleURL={buildTunnelPreviewURL(relayUrls[0] ?? "", name)}
              os={os}
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

      {auth.method !== "none" && (
        <VisitorPreview
          auth={auth}
          relayURL={relayUrls[0] ?? ""}
          name={name}
        />
      )}
    </div>
  );
}
