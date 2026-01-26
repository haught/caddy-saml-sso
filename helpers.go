package caddy_saml_sso

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

func (m *Middleware) extractAttributes(r *http.Request) (Attributes, error) {
	session, err := m.SamlSP.Session.GetSession(r)
	if err != nil {
		logDebug("failed to get SAML session: %v", err)
		return nil, nil
	}
	if session == nil {
		return nil, nil
	}

	jwtSessionClaims, ok := session.(SamlJWTSessionClaims)
	if !ok {
		return nil, fmt.Errorf("unable to decode session into JWTSessionClaims")
	}

	return jwtSessionClaims.Attributes, nil
}

// sanitizeHeaderValue removes CR and LF characters from a string to prevent
// HTTP header injection attacks.
func sanitizeHeaderValue(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

func logDebug(msg string, args ...any) {
	caddy.Log().Sugar().Debugf(msg, args...)
}

func logInfo(msg string, args ...any) {
	caddy.Log().Sugar().Infof(msg, args...)
}

func logWarn(msg string, args ...any) {
	caddy.Log().Sugar().Warnf(msg, args...)
}

func logError(msg string, args ...any) {
	caddy.Log().Sugar().Errorf(msg, args...)
}
