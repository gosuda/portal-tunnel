import { TUNNEL_FORM_STYLES as s } from "@/components/TunnelFormParts";
import { Badge } from "./authShared";
import signinCopy from "@/lib/signinCopy.json";
import { cn } from "@/lib/utils";
import {
  buildServiceStatusHostname,
  type TunnelAuthOptions,
} from "@/lib/tunnelCommand";

export function VisitorPreview({
  auth,
  relayURL,
  name,
}: {
  auth: TunnelAuthOptions;
  relayURL: string;
  name: string;
}) {
  const hostname =
    buildServiceStatusHostname(relayURL, name) || "your-name.relay";
  let issuerHost = "your provider";
  try {
    const provider = auth.method === "saml" ? auth.samlMetadataURL : auth.oidcIssuer;
    issuerHost = new URL(provider.trim()).hostname || issuerHost;
  } catch {
    // The address is still being typed.
  }
  // The credential, wallet and email texts are those of the sign-in pages; the
  // gate test (sdk/appauth/signin_page_test.go) fails when a page and signinCopy.json differ.
  // OIDC and SAML leave for the provider at once and have no page of their own.
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
        className={cn("rounded-lg border px-4 py-5 text-center", s.preview)}
      >
        <Badge>{hostname}</Badge>
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
