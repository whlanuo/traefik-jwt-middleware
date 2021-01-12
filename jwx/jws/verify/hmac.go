package verify

import (
	"crypto/hmac"
	jwa2 "github.com/whlanuo/traefik-jwt-middleware/jwx/jwa"
	sign2 "github.com/whlanuo/traefik-jwt-middleware/jwx/jws/sign"

	"github.com/whlanuo/traefik-jwt-middleware/errors"
)

func newHMAC(alg jwa2.SignatureAlgorithm) (*HMACVerifier, error) {
	_, ok := sign2.HMACSignFuncs[alg]
	if !ok {
		return nil, errors.Errorf(`unsupported algorithm while trying to create HMAC signer: %s`, alg)
	}
	s, err := sign2.New(alg)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate HMAC signer`)
	}
	return &HMACVerifier{signer: s}, nil
}

func (v HMACVerifier) Verify(payload, signature []byte, key interface{}) (err error) {
	expected, err := v.signer.Sign(payload, key)
	if err != nil {
		return errors.Wrap(err, `failed to generated signature`)
	}

	if !hmac.Equal(signature, expected) {
		return errors.New(`failed to match hmac signature`)
	}
	return nil
}
