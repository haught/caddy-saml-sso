package caddy_saml_sso

import (
	"net/http"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/crewjam/saml/samlsp"
)

// Holds all the module's data
type Middleware struct {
	SamlIdpUrl       string   `json:"saml_idp_url,omitempty"`
	SamlCertFile     string   `json:"saml_cert_file,omitempty"`
	SamlKeyFile      string   `json:"saml_cert_key,omitempty"`
	SamlRootUrl      string   `json:"saml_root_url,omitempty"`
	SamlEntityID     string   `json:"saml_entity_id,omitempty"`
	SamlClaims       []string `json:"saml_claims,omitempty"`
	SamlHeaderClaims []string `json:"saml_header_claims,omitempty"`

	SamlSP      *samlsp.Middleware
	SamlHandler http.Handler
}

func init() {
	caddy.RegisterModule(Middleware{})
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	log("middleware path=%s", r.URL.Path)

	// If the request is part of the SAML flow,
	// handle the request with the SAML library
	if strings.HasPrefix(r.URL.Path, "/saml") {
		m.SamlSP.ServeHTTP(w, r)
		return nil
	} else {
		// before going down the middleware stack, make sure
		// we are in a SAML session
		m.SamlHandler.ServeHTTP(w, r)

		// Let's grab the SAML session attributes and add them to the header
		// so other services can use it
		attributes, err := m.extractAttributes(r)
		if attributes != nil && err == nil {
			log("number of attributes=%d", len(attributes))
			for k, v := range attributes {
				if len(v) > 0 && (len(m.SamlHeaderClaims) == 0 || slices.Contains(m.SamlHeaderClaims, k)) {
					if w.Header().Get(k) == "" {
						w.Header().Add(k, strings.Join(v, ","))
					}
				}
			}
		} else {
			log("attributes=%v err=%s", attributes, err)
		}
		log("saml_sso v%s middlware done", version)
		return next.ServeHTTP(w, r)
	}
}
