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
	SamlIdpUrl        string   `json:"saml_idp_url,omitempty"`
	SamlCertFile      string   `json:"saml_cert_file,omitempty"`
	SamlKeyFile       string   `json:"saml_cert_key,omitempty"`
	SamlRootUrl       string   `json:"saml_root_url,omitempty"`
	SamlEntityID      string   `json:"saml_entity_id,omitempty"`
	SamlUserIdClaim   string   `json:"saml_userid_claim,omitempty"`
	SamlClaims        []string `json:"saml_claims,omitempty"`
	SamlCookieName    string   `json:"saml_cookie_name,omitempty"`
	SamlRemoteUserVar string   `json:"saml_remote_user_var,omitempty"`
	SamlVarPrefix     string   `json:"saml_var_prefix,omitempty"`
	SamlSP            *samlsp.Middleware
	SamlHandler       http.Handler
}

func init() {
	caddy.RegisterModule(Middleware{})
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	logDebug("saml_sso v%s middleware starting", version)
	// If the request is part of the SAML flow,
	// handle the request with the SAML library
	if strings.HasPrefix(r.URL.Path, "/saml") {
		m.SamlSP.ServeHTTP(w, r)
		return nil
	} else {
		// before going down the middleware stack, make sure
		// we are in a SAML session
		if m.SamlHandler == nil {
			logError("saml_sso SamlHandler is empty")
			http.Error(w, "SAML handler not initialized", http.StatusInternalServerError)
			return nil
		}
		m.SamlHandler.ServeHTTP(w, r)

		// If we have a user id claim, we need to delete the remote user header from the request
		if len(m.SamlUserIdClaim) > 0 {
			r.Header.Del("X-Remote-User")
		}
		// If we have a header claims, we need to add them to the header
		// Let's grab the SAML session attributes and add them to the header
		// so other services can use it
		attributes, err := m.extractAttributes(r)
		if attributes != nil && err == nil {
			for k, v := range attributes {
				// If we have a user id claim, we need to add it to the request header and caddy variable
				if len(m.SamlUserIdClaim) > 0 && k == m.SamlUserIdClaim {
					logDebug("setting saml_ssoremote user header to %s", v[0])
					r.Header.Set("X-Remote-User", v[0])
					logDebug("setting saml_ssovariable for %s to '%s'", m.SamlRemoteUserVar, v[0])
					caddyhttp.SetVar(r.Context(), m.SamlRemoteUserVar, v[0])
				} else if slices.Contains(m.SamlClaims, k) {
					logDebug("setting saml_ssovariable for %s to '%s'", m.SamlVarPrefix+strings.ToUpper(k), strings.Join(v, ","))
					caddyhttp.SetVar(r.Context(), m.SamlVarPrefix+strings.ToUpper(k), strings.Join(v, ","))
				}
			}
		} else {
			if err != nil {
				logError("error extracting saml_sso attributes: %s", err)
			}
		}
		logDebug("saml_sso v%s middleware done", version)
		return next.ServeHTTP(w, r)
	}
}
