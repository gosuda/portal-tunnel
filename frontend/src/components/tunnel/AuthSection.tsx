import { useId } from "react";
import {
  Building2,
  Globe,
  Link2,
  Mail,
  ShieldCheck,
  Wallet,
  type LucideIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/chip";
import { AllowList } from "./AllowList";
import { InviteBlock } from "./InviteBlock";
import { EmailSetup, OIDCSetup, SAMLSetup } from "./ProviderSetup";
import { Hint } from "./fields";
import signinCopy from "@/lib/signinCopy.json";
import {
  buildServiceStatusHostname,
  buildTunnelPreviewURL,
  type TunnelAuthIssue,
  type TunnelAuthMethod,
  type TunnelAuthOptions,
  type TunnelCommandOS,
} from "@/lib/tunnelCommand";

const METHODS: { id: TunnelAuthMethod; label: string; icon: LucideIcon }[] = [
  { id: "none", label: "No sign-in", icon: Globe },
  { id: "credential", label: "Private link", icon: Link2 },
  { id: "siwe", label: "Ethereum wallet", icon: Wallet },
  { id: "oidc", label: "Google or company login", icon: ShieldCheck },
  { id: "saml", label: "Company single sign-on", icon: Building2 },
  { id: "email", label: "Email link", icon: Mail },
];

interface AuthSectionProps {
  auth: TunnelAuthOptions;
  onChange: (next: TunnelAuthOptions) => void;
  issues: TunnelAuthIssue[];
  relayUrls: string[];
  discovery: boolean;
  name: string;
  os: TunnelCommandOS;
}

export function AuthSection({
  auth,
  onChange,
  issues,
  relayUrls,
  discovery,
  name,
  os,
}: AuthSectionProps) {
  const groupName = useId();
  const patch = (next: Partial<TunnelAuthOptions>) =>
    onChange({ ...auth, ...next });
  const host = { relayUrls, discovery, name };

  return (
    <div className="space-y-4">
      <div
        role="radiogroup"
        aria-label="Who can open it"
        className="grid grid-cols-1 gap-2 min-[480px]:grid-cols-2"
      >
        {METHODS.map(({ id, label, icon: Icon }) => (
          <label
            key={id}
            className="interactive flex h-10 cursor-pointer items-center gap-2.5 rounded-md border border-stroke px-3 text-sm font-semibold text-content-emphasis has-checked:border-primary has-checked:bg-state-hover has-focus-visible:outline-3 has-focus-visible:outline-focus"
          >
            <input
              type="radio"
              name={groupName}
              className="sr-only"
              checked={auth.method === id}
              onChange={() => patch({ method: id, allow: [] })}
            />
            <Icon aria-hidden="true" className="size-4 shrink-0" />
            {label}
          </label>
        ))}
      </div>

      {auth.method !== "none" && (
        <div className="space-y-5 rounded-lg border border-stroke bg-surface-100 p-4">
          <AllowList key={auth.method} auth={auth} patch={patch} issues={issues} />
          {auth.method === "oidc" && (
            <OIDCSetup auth={auth} patch={patch} issues={issues} os={os} {...host} />
          )}
          {auth.method === "saml" && (
            <SAMLSetup auth={auth} patch={patch} issues={issues} {...host} />
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
          <label className="flex cursor-pointer items-start gap-2.5 text-sm text-content-emphasis">
            <input
              type="checkbox"
              checked={auth.identityHeaders}
              onChange={(event) =>
                patch({ identityHeaders: event.target.checked })
              }
              className="mt-0.5 size-4"
            />
            <span>
              Pass the visitor's identity to my app
              <Hint>
                Adds <code>X-Portal-User</code> and <code>X-Portal-Auth</code>.
                Only safe if the app can be reached through Portal alone.
              </Hint>
            </span>
          </label>
        </div>
      )}

      {auth.method !== "none" && (
        <VisitorPreview auth={auth} relayURL={relayUrls[0] ?? ""} name={name} />
      )}
    </div>
  );
}

function VisitorPreview({
  auth,
  relayURL,
  name,
}: {
  auth: TunnelAuthOptions;
  relayURL: string;
  name: string;
}) {
  const hostname = buildServiceStatusHostname(relayURL, name) || "your-name.relay";
  const issuerHost = hostnameOf(auth.method === "saml" ? auth.samlMetadataURL : auth.oidcIssuer) ?? "your provider";
  const sentToProvider = {
    title: `You are sent to ${issuerHost}`,
    body: "They sign in there and come back to the app.",
    action: "",
  };
  const page = {
    credential: signinCopy.credential,
    siwe: signinCopy.siwe,
    email: signinCopy.email,
    oidc: sentToProvider,
    saml: sentToProvider,
    none: { title: "", body: "", action: "" },
  }[auth.method];

  return (
    <div className="space-y-1.5">
      <div
        aria-hidden="true"
        className="rounded-lg border border-stroke bg-surface-0 px-4 py-5 text-center"
      >
        <Badge>{hostname}</Badge>
        <p className="mt-2 text-sm font-semibold text-content-emphasis">
          {page.title}
        </p>
        <p className="mx-auto mt-1 max-w-[36ch] text-xs leading-5 text-content-muted">
          {page.body}
        </p>
        {page.action !== "" && (
          <span className="mt-3 inline-block rounded-md bg-primary px-4 py-1.5 text-xs font-bold text-primary-content">
            {page.action}
          </span>
        )}
      </div>
      <p className="text-center text-xs text-content-muted">
        What a visitor sees first (illustrative)
      </p>
    </div>
  );
}

function hostnameOf(address: string): string | null {
  try {
    return new URL(address.trim()).hostname || null;
  } catch {
    return null;
  }
}
