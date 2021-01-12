package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	jwa2 "github.com/whlanuo/traefik-jwt-middleware/jwx/jwa"
	"hash"

	"github.com/whlanuo/traefik-jwt-middleware/errors"
)

var HMACSignFuncs = map[jwa2.SignatureAlgorithm]hmacSignFunc{}

func init() {
	algs := map[jwa2.SignatureAlgorithm]func() hash.Hash{
		jwa2.HS256: sha256.New,
		jwa2.HS384: sha512.New384,
		jwa2.HS512: sha512.New,
	}

	for alg, h := range algs {
		HMACSignFuncs[alg] = makeHMACSignFunc(h)
	}
}

func newHMAC(alg jwa2.SignatureAlgorithm) (*HMACSigner, error) {
	signer, ok := HMACSignFuncs[alg]
	if !ok {
		return nil, errors.Errorf(`unsupported algorithm while trying to create HMAC signer: %s`, alg)
	}

	return &HMACSigner{
		alg:  alg,
		sign: signer,
	}, nil
}

func makeHMACSignFunc(hfunc func() hash.Hash) hmacSignFunc {
	return func(payload []byte, key []byte) ([]byte, error) {
		h := hmac.New(hfunc, key)
		if _, err := h.Write(payload); err != nil {
			return nil, errors.Wrap(err, "failed to write payload using hmac")
		}
		return h.Sum(nil), nil
	}
}

func (s HMACSigner) Algorithm() jwa2.SignatureAlgorithm {
	return s.alg
}

func (s HMACSigner) Sign(payload []byte, key interface{}) ([]byte, error) {
	hmackey, ok := key.([]byte)
	if !ok {
		return nil, errors.Errorf(`invalid key type %T. []byte is required`, key)
	}

	if len(hmackey) == 0 {
		return nil, errors.New(`missing key while signing payload`)
	}

	return s.sign(payload, hmackey)
}
