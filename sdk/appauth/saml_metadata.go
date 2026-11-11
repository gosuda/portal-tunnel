package appauth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	samltypes "github.com/russellhaering/gosaml2/types"
)

func (s *samlAuthenticator) identityProvider(ctx context.Context) (samlIdentityProvider, error) {
	return s.metadata.get(ctx, providerMetadataCacheTTL, s.fetchMetadata)
}

func (s *samlAuthenticator) fetchMetadata(ctx context.Context) (samlIdentityProvider, error) {
	var data []byte
	var err error
	if s.metadataFile != "" {
		data, err = readSAMLMetadataFile(s.metadataFile)
	} else {
		data, err = fetchSAMLMetadata(ctx, s.httpClient, s.metadataURL)
	}
	if err != nil {
		return samlIdentityProvider{}, fmt.Errorf("read saml metadata: %w", err)
	}
	return parseSAMLMetadata(data)
}

func readSAMLMetadataFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return readSAMLMetadata(file)
}

func fetchSAMLMetadata(ctx context.Context, client *http.Client, targetURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return readSAMLMetadata(resp.Body)
}

func readSAMLMetadata(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, samlMetadataBodyLimit+1))
	if err == nil && len(data) > samlMetadataBodyLimit {
		err = errSAMLMetadataTooLarge
	}
	return data, err
}

func parseSAMLMetadata(data []byte) (samlIdentityProvider, error) {
	entities, err := decodeParseSAMLMetadataEntities(data)
	if err != nil {
		return samlIdentityProvider{}, err
	}
	entity, entityID, err := selectParseSAMLMetadataIDP(entities)
	if err != nil {
		return samlIdentityProvider{}, err
	}
	descriptor := entity.IDPSSODescriptor
	ssoURL, err := findParseSAMLMetadataSSOURL(descriptor)
	if err != nil {
		return samlIdentityProvider{}, err
	}
	certs, err := collectSigningCerts(descriptor)
	if err != nil {
		return samlIdentityProvider{}, err
	}
	if err := validateSigningCerts(certs); err != nil {
		return samlIdentityProvider{}, err
	}
	return samlIdentityProvider{entityID: entityID, ssoURL: ssoURL, certs: certs}, nil
}

func decodeParseSAMLMetadataEntities(data []byte) ([]samltypes.EntityDescriptor, error) {
	var entity samltypes.EntityDescriptor
	err := xml.Unmarshal(data, &entity)
	if err == nil {
		return []samltypes.EntityDescriptor{entity}, nil
	}
	var list samlEntitiesDescriptor
	if xml.Unmarshal(data, &list) != nil {
		return nil, fmt.Errorf("parse saml metadata: %w", err)
	}
	return list.Entities, nil
}

func selectParseSAMLMetadataIDP(entities []samltypes.EntityDescriptor) (samltypes.EntityDescriptor, string, error) {
	var idps []samltypes.EntityDescriptor
	for _, entity := range entities {
		if entity.IDPSSODescriptor != nil {
			idps = append(idps, entity)
		}
	}
	if len(idps) != 1 {
		return samltypes.EntityDescriptor{}, "", errSAMLMetadataNoIdentityProvider
	}
	entityID := strings.TrimSpace(idps[0].EntityID)
	if entityID == "" {
		return samltypes.EntityDescriptor{}, "", errSAMLMetadataNoEntityID
	}
	return idps[0], entityID, nil
}

func findParseSAMLMetadataSSOURL(descriptor *samltypes.IDPSSODescriptor) (string, error) {
	for _, service := range descriptor.SingleSignOnServices {
		if service.Binding != saml2.BindingHttpRedirect {
			continue
		}
		location, err := url.Parse(strings.TrimSpace(service.Location))
		wellFormed := err == nil && location.Host != "" && location.User == nil && location.Fragment == ""
		if !wellFormed || !secureSAMLProviderURL(location) {
			return "", fmt.Errorf("saml single sign-on service must be an https url (or http on a loopback host): %q", service.Location)
		}
		return location.String(), nil
	}
	return "", errSAMLMetadataNoRedirectSSO
}

func collectSigningCerts(descriptor *samltypes.IDPSSODescriptor) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, key := range descriptor.KeyDescriptors {
		if key.Use != "" && key.Use != "signing" {
			continue
		}
		for _, cert := range key.KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(cert.Data), ""))
			if err != nil {
				return nil, fmt.Errorf("saml metadata signing certificate: %w", err)
			}
			parsed, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("saml metadata signing certificate: %w", err)
			}
			certs = append(certs, parsed)
		}
	}
	return certs, nil
}

func validateSigningCerts(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return errSAMLMetadataNoSigningKey
	}
	now := time.Now()
	if !slices.ContainsFunc(certs, func(cert *x509.Certificate) bool {
		return !now.Before(cert.NotBefore) && !now.After(cert.NotAfter)
	}) {
		return errSAMLMetadataNoValidSigningKey
	}
	return nil
}
