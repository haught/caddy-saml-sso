package caddy_saml_sso

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
)

func (m *Middleware) extractAttributes(r *http.Request) (Attributes, error) {
	session, _ := m.SamlSP.Session.GetSession(r)
	if session == nil {
		return nil, nil
	}

	jwtSessionClaims, ok := session.(SamlJWTSessionClaims)
	if !ok {
		return nil, fmt.Errorf("unable to decode session into JWTSessionClaims")
	}

	return jwtSessionClaims.Attributes, nil
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
