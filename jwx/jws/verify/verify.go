package verify

import (
	"github.com/whlanuo/traefik-jwt-middleware/errors"
	"github.com/whlanuo/traefik-jwt-middleware/jwx/jwa"
)

// New creates a new JWS verifier using the specified algorithm
// and the public key
func New(alg jwa.SignatureAlgorithm) (Verifier, error) {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
		return newRSA(alg)
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return newHMAC(alg)
	default:
		return nil, errors.Errorf(`unsupported signature algorithm: %#v`, alg)
	}
}
