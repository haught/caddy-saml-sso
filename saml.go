package caddy_saml_sso

import (
	"github.com/golang-jwt/jwt/v4"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

var defaultJWTSigningMethod = jwt.SigningMethodRS256

const defaultSessionCookieName = "token"

// SamltSessionCodec returns the default SessionCodec for the provided options,
// a SamlJWTSessionCodec configured to issue signed tokens.
func SamlSessionCodec(opts samlsp.Options, claims []string) SamlJWTSessionCodec {
	return SamlJWTSessionCodec{
		SigningMethod: defaultJWTSigningMethod,
		Audience:      opts.URL.String(),
		Issuer:        opts.URL.String(),
		MaxAge:        defaultSessionMaxAge,
		Key:           opts.Key,
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
	return samlsp.CookieSessionProvider{
		Name:     cookieName,
		Domain:   opts.URL.Host,
		MaxAge:   defaultSessionMaxAge,
		HTTPOnly: true,
		Secure:   opts.URL.Scheme == "https",
		SameSite: opts.CookieSameSite,
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
	m := &samlsp.Middleware{
		ServiceProvider: samlsp.DefaultServiceProvider(opts),
		Binding:         "",
		ResponseBinding: saml.HTTPPostBinding,
		OnError:         samlsp.DefaultOnError,
		Session:         SamlSessionProvider(opts, claims),
	}
	m.RequestTracker = samlsp.DefaultRequestTracker(opts, &m.ServiceProvider)
	if opts.UseArtifactResponse {
		m.ResponseBinding = saml.HTTPArtifactBinding
	}

	return m, nil
}
