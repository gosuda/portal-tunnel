import type { JSX } from "react";
import { CopyLine, RegisterNote, TextField } from "./authShared";
import { TUNNEL_FORM_STYLES as s } from "@/components/TunnelFormParts";
import { AUTH_SAML_ACS_PATH, AUTH_SAML_METADATA_PATH } from "@/lib/apiPaths";
import {
  buildAuthRedirectURLs,
  type TunnelAuthIssue,
  type TunnelAuthOptions,
} from "@/lib/tunnelCommand";

export function SAMLSetup({
  auth,
  patch,
  issues,
  relayUrls,
  discovery,
  name,
}: {
  auth: TunnelAuthOptions;
  patch: (next: Partial<TunnelAuthOptions>) => void;
  issues: TunnelAuthIssue[];
  relayUrls: string[];
  discovery: boolean;
  name: string;
}): JSX.Element {
  const acsURLs = buildAuthRedirectURLs(relayUrls, name, AUTH_SAML_ACS_PATH);
  const metadataURLs = buildAuthRedirectURLs(relayUrls, name, AUTH_SAML_METADATA_PATH);

  return (
    <div className="space-y-4">
      <div className="space-y-3">
        <TextField
          label="Identity provider metadata"
          inputMode="url"
          value={auth.samlMetadataURL}
          onChange={(samlMetadataURL) => patch({ samlMetadataURL })}
          placeholder="https://idp.example.com/metadata"
          issues={issues}
          field="metadataURL"
        >
          <p className={s.help}>
            The address where the provider publishes its SAML metadata, such
            as Keycloak's <code>/protocol/saml/descriptor</code>. For a
            provider that only gives you a file, replace this flag with{" "}
            <code>--auth-saml-metadata-file</code> and the file's path.
          </p>
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
        <p className={s.help}>
          The subject is the NameID unless you name an attribute, such as{" "}
          <code>email</code>. SAML does not say whether an email was verified,
          so Portal trusts the address the provider signs: let the provider
          send only addresses its users cannot change.
        </p>
      </div>

      <div className="space-y-1.5">
        <p className={s.label}>At your identity provider</p>
        <p className={s.help}>
          Add a SAML application. Import its metadata from the metadata
          address, or enter the ACS address with the HTTP-POST binding and the
          entity ID by hand. Have the provider sign the response or the
          assertion. Portal sends unsigned requests and does not accept
          encrypted assertions, and it accepts only sign-ins that start at the
          app, not at the provider's app list.
        </p>
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
