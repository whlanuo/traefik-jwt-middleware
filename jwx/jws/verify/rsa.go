package verify

import (
	"crypto"
	"crypto/rsa"
	jwa2 "github.com/whlanuo/traefik-jwt-middleware/jwx/jwa"

	"github.com/whlanuo/traefik-jwt-middleware/errors"
)

var rsaVerifyFuncs = map[jwa2.SignatureAlgorithm]rsaVerifyFunc{}

func init() {
	algs := map[jwa2.SignatureAlgorithm]struct {
		Hash       crypto.Hash
		VerifyFunc func(crypto.Hash) rsaVerifyFunc
	}{
		jwa2.RS256: {
			Hash:       crypto.SHA256,
			VerifyFunc: makeVerifyPKCS1v15,
		},
		jwa2.RS384: {
			Hash:       crypto.SHA384,
			VerifyFunc: makeVerifyPKCS1v15,
		},
		jwa2.RS512: {
			Hash:       crypto.SHA512,
			VerifyFunc: makeVerifyPKCS1v15,
		},
		jwa2.PS256: {
			Hash:       crypto.SHA256,
			VerifyFunc: makeVerifyPSS,
		},
		jwa2.PS384: {
			Hash:       crypto.SHA384,
			VerifyFunc: makeVerifyPSS,
		},
		jwa2.PS512: {
			Hash:       crypto.SHA512,
			VerifyFunc: makeVerifyPSS,
		},
	}

	for alg, item := range algs {
		rsaVerifyFuncs[alg] = item.VerifyFunc(item.Hash)
	}
}

func makeVerifyPKCS1v15(hash crypto.Hash) rsaVerifyFunc {
	return func(payload, signature []byte, key *rsa.PublicKey) error {
		h := hash.New()
		if _, err := h.Write(payload); err != nil {
			return errors.Wrap(err, "failed to write payload using PKCS1v15")
		}

		return rsa.VerifyPKCS1v15(key, hash, h.Sum(nil), signature)
	}
}

func makeVerifyPSS(hash crypto.Hash) rsaVerifyFunc {
	return func(payload, signature []byte, key *rsa.PublicKey) error {
		h := hash.New()
		if _, err := h.Write(payload); err != nil {
			return errors.Wrap(err, "failed to write payload using PSS")
		}
		return rsa.VerifyPSS(key, hash, h.Sum(nil), signature, nil)
	}
}

func newRSA(alg jwa2.SignatureAlgorithm) (*RSAVerifier, error) {
	verifyfn, ok := rsaVerifyFuncs[alg]
	if !ok {
		return nil, errors.Errorf(`unsupported algorithm while trying to create RSA verifier: %s`, alg)
	}

	return &RSAVerifier{
		verify: verifyfn,
	}, nil
}

func (v RSAVerifier) Verify(payload, signature []byte, key interface{}) error {
	if key == nil {
		return errors.New(`missing public key while verifying payload`)
	}

	var pubkey *rsa.PublicKey
	switch v := key.(type) {
	case rsa.PublicKey:
		pubkey = &v
	case *rsa.PublicKey:
		pubkey = v
	default:
		return errors.Errorf(`invalid key type %T. *rsa.PublicKey is required`, key)
	}

	return v.verify(payload, signature, pubkey)
}
