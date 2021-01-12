package sign

import (
	"github.com/whlanuo/traefik-jwt-middleware/errors"
	"github.com/whlanuo/traefik-jwt-middleware/jwx/jwa"
)

// New creates a signer that signs payloads using the given signature algorithm.
func New(alg jwa.SignatureAlgorithm) (Signer, error) {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
		return newRSA(alg)
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return newHMAC(alg)
	default:
		return nil, errors.Errorf(`unsupported signature algorithm %s`, alg)
	}
}
