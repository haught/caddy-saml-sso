package caddy_saml_sso

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

const (
	defaultSessionMaxAge  = time.Hour
	claimNameSessionIndex = "SessionIndex"
)

// SamlJWTSessionCodec implements SessionCoded to encode and decode Sessions from
// the corresponding JWT.
type SamlJWTSessionCodec struct {
	SigningMethod jwt.SigningMethod
	Audience      string
	Issuer        string
	MaxAge        time.Duration
	Key           *rsa.PrivateKey
	Claims        []string
}

// New creates a Session from the SAML assertion.
//
// The returned Session is a SamlJWTSessionClaims.
func (c SamlJWTSessionCodec) New(assertion *saml.Assertion) (samlsp.Session, error) {
	now := saml.TimeNow()
	claims := SamlJWTSessionClaims{}
	claims.SAMLSession = true
	claims.Audience = c.Audience
	claims.Issuer = c.Issuer
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(c.MaxAge).Unix()
	claims.NotBefore = now.Unix()

	if sub := assertion.Subject; sub != nil {
		if nameID := sub.NameID; nameID != nil {
			claims.Subject = nameID.Value
		}
	}

	claims.Attributes = map[string][]string{}

	for _, attributeStatement := range assertion.AttributeStatements {
		for _, attr := range attributeStatement.Attributes {
			claimName := attr.FriendlyName
			if claimName == "" {
				claimName = attr.Name
			}
			if len(c.Claims) == 0 || slices.Contains(c.Claims, claimName) {
				for _, value := range attr.Values {
					claims.Attributes[claimName] = append(claims.Attributes[claimName], value.Value)
				}
			}
		}
	}

	// add SessionIndex to claims Attributes
	for _, authnStatement := range assertion.AuthnStatements {
		claims.Attributes[claimNameSessionIndex] = append(claims.Attributes[claimNameSessionIndex],
			authnStatement.SessionIndex)
	}

	return claims, nil
}

// Encode returns a serialized version of the Session.
//
// The provided session must be a SamlJWTSessionClaims, otherwise this
// function will panic.
func (c SamlJWTSessionCodec) Encode(s samlsp.Session) (string, error) {
	claims := s.(SamlJWTSessionClaims) // this will panic if you pass the wrong kind of session
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedString, err := token.SignedString(c.Key)
	if err != nil {
		return "", err
	}

	return signedString, nil
}

// Decode parses the serialized session that may have been returned by Encode
// and returns a Session.
func (c SamlJWTSessionCodec) Decode(signed string) (samlsp.Session, error) {
	parser := jwt.Parser{
		ValidMethods: []string{c.SigningMethod.Alg()},
	}
	claims := SamlJWTSessionClaims{}
	_, err := parser.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
		return c.Key.Public(), nil
	})
	// TODO(ross): check for errors due to bad time and return ErrNoSession
	if err != nil {
		return nil, err
	}
	if !claims.VerifyAudience(c.Audience, true) {
		return nil, fmt.Errorf("expected audience %q, got %q", c.Audience, claims.Audience)
	}
	if !claims.VerifyIssuer(c.Issuer, true) {
		return nil, fmt.Errorf("expected issuer %q, got %q", c.Issuer, claims.Issuer)
	}
	if !claims.SAMLSession {
		return nil, errors.New("expected saml-session")
	}
	return claims, nil
}

// SamlJWTSessionClaims represents the JWT claims in the encoded session
type SamlJWTSessionClaims struct {
	jwt.StandardClaims
	Attributes  Attributes `json:"attr"`
	SAMLSession bool       `json:"saml-session"`
}

//var _ samlsp.Session = SamlJWTSessionClaims{}

// GetAttributes implements SessionWithAttributes. It returns the SAMl attributes.
func (c SamlJWTSessionClaims) GetAttributes() Attributes {
	return c.Attributes
}

// Attributes is a map of attributes provided in the SAML assertion
type Attributes map[string][]string

// Get returns the first attribute named `key` or an empty string if
// no such attributes is present.
func (a Attributes) Get(key string) string {
	if a == nil {
		return ""
	}
	v := a[key]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
