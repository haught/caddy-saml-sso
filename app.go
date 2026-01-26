package caddy_saml_sso

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/crewjam/saml/samlsp"
)

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.saml_sso",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Middleware) Provision(ctx caddy.Context) error {
	// Set defaults for optional fields
	if m.SamlCookieName == "" {
		m.SamlCookieName = "token"
	}
	if m.SamlRemoteUserVar == "" {
		m.SamlRemoteUserVar = "REMOTE_USER"
	}
	if m.SamlVarPrefix == "" {
		m.SamlVarPrefix = "SAML_"
	}

	keyPair, err := tls.LoadX509KeyPair(m.SamlCertFile, m.SamlKeyFile)
	if err != nil {
		return err
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return err
	}

	idpMetadataURL, err := url.Parse(m.SamlIdpUrl)
	if err != nil {
		return err
	}

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		return err
	}

	rootURL, err := url.Parse(m.SamlRootUrl)
	if err != nil {
		return err
	}

	// Parse SameSite setting
	var sameSite http.SameSite
	switch m.SamlCookieSameSite {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "lax":
		sameSite = http.SameSiteLaxMode
	case "none":
		sameSite = http.SameSiteNoneMode
	default:
		sameSite = 0 // Let SamlSessionProvider use its default (Lax)
	}

	samlSP, err := NewSaml(samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadata:    idpMetadata,
		EntityID:       m.SamlEntityID,
		SignRequest:    true,
		CookieName:     m.SamlCookieName,
		CookieSameSite: sameSite,
	}, m.SamlClaims)
	if err != nil {
		return err
	}

	m.SamlSP = samlSP
	nullHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	m.SamlHandler = samlSP.RequireAccount(nullHandler)

	logDebug("loaded saml_sso v%s", version)
	return nil
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	if m.SamlIdpUrl == "" {
		return fmt.Errorf("saml_idp_url is required")
	}
	if m.SamlCertFile == "" {
		return fmt.Errorf("saml_cert_file is required")
	}
	if m.SamlKeyFile == "" {
		return fmt.Errorf("saml_key_file is required")
	}
	if m.SamlRootUrl == "" {
		return fmt.Errorf("saml_root_url is required")
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
