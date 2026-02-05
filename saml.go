package caddy_saml_sso

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v4"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

const defaultSessionCookieName = "token"

// SamltSessionCodec returns the default SessionCodec for the provided options,
// a SamlJWTSessionCodec configured to issue signed tokens.
func SamlSessionCodec(opts samlsp.Options, claims []string) SamlJWTSessionCodec {
	key := opts.Key.(crypto.Signer)

	// Select signing method based on key type
	var signingMethod jwt.SigningMethod
	switch key.Public().(type) {
	case *rsa.PublicKey:
		signingMethod = jwt.SigningMethodRS256
	case *ecdsa.PublicKey:
		signingMethod = jwt.SigningMethodES256
	default:
		signingMethod = jwt.SigningMethodRS256 // fallback
	}

	return SamlJWTSessionCodec{
		SigningMethod: signingMethod,
		Audience:      opts.URL.String(),
		Issuer:        opts.URL.String(),
		MaxAge:        defaultSessionMaxAge,
		Key:           key,
		Claims:        claims,
	}
}

// SamlSessionProvider returns the default SessionProvider for the provided options,
// a CookieSessionProvider configured to store sessions in a cookie.
func SamlSessionProvider(opts samlsp.Options, claims []string) samlsp.CookieSessionProvider {
	cookieName := opts.CookieName
	if cookieName == "" {
		cookieName = defaultSessionCookieName
	}
	// Default to SameSite=Lax if not explicitly configured to prevent CSRF attacks
	sameSite := opts.CookieSameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}
	return samlsp.CookieSessionProvider{
		Name:     cookieName,
		Domain:   opts.URL.Host,
		MaxAge:   defaultSessionMaxAge,
		HTTPOnly: true,
		Secure:   opts.URL.Scheme == "https",
		SameSite: sameSite,
		Codec:    SamlSessionCodec(opts, claims),
	}
}

// NewSaml creates a new Middleware with the default providers for the
// given options.
//
// You can customize the behavior of the middleware in more detail by
// replacing and/or changing Session, RequestTracker, and ServiceProvider
// in the returned Middleware.
func NewSaml(opts samlsp.Options, claims []string) (*samlsp.Middleware, error) {
	// Validate required options
	if opts.URL.String() == "" {
		return nil, fmt.Errorf("URL is required")
	}
	if opts.Key == nil {
		return nil, fmt.Errorf("key is required")
	}
	if opts.Certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if opts.IDPMetadata == nil {
		return nil, fmt.Errorf("IDPMetadata is required")
	}

	sp := samlsp.DefaultServiceProvider(opts)
	if sp.EntityID == "" {
		return nil, fmt.Errorf("ServiceProvider EntityID is empty")
	}

	session := SamlSessionProvider(opts, claims)
	if session.Codec == nil {
		return nil, fmt.Errorf("session codec is nil")
	}

	m := &samlsp.Middleware{
		ServiceProvider:  sp,
		Binding:          "",
		ResponseBinding:  saml.HTTPPostBinding,
		OnError:          samlsp.DefaultOnError,
		Session:          session,
		AssertionHandler: samlsp.DefaultAssertionHandler(opts),
	}

	m.RequestTracker = samlsp.DefaultRequestTracker(opts, &m.ServiceProvider)
	if m.RequestTracker == nil {
		return nil, fmt.Errorf("RequestTracker is nil after initialization")
	}

	if opts.UseArtifactResponse {
		m.ResponseBinding = saml.HTTPArtifactBinding
	}

	// Validate all critical fields are set
	if m.ServiceProvider.EntityID == "" {
		return nil, fmt.Errorf("ServiceProvider EntityID is empty")
	}
	if m.Session == nil {
		return nil, fmt.Errorf("session is empty")
	}

	return m, nil
}
