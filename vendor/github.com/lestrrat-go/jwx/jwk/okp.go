package jwk

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"fmt"

	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/internal/blackmagic"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/x25519"
	"github.com/pkg/errors"
)

func NewOKPPublicKey() OKPPublicKey {
	return newOKPPublicKey()
}

func newOKPPublicKey() *okpPublicKey {
	return &okpPublicKey{
		privateParams: make(map[string]interface{}),
	}
}

func NewOKPPrivateKey() OKPPrivateKey {
	return newOKPPrivateKey()
}

func newOKPPrivateKey() *okpPrivateKey {
	return &okpPrivateKey{
		privateParams: make(map[string]interface{}),
	}
}

func (k *okpPublicKey) FromRaw(rawKeyIf interface{}) error {
	switch rawKey := rawKeyIf.(type) {
	case ed25519.PublicKey:
		k.x = rawKey
		if err := k.Set(OKPCrvKey, jwa.Ed25519); err != nil {
			return errors.Wrap(err, `failed to set header`)
		}
	case x25519.PublicKey:
		k.x = rawKey
		if err := k.Set(OKPCrvKey, jwa.X25519); err != nil {
			return errors.Wrap(err, `failed to set header`)
		}
	default:
		return errors.Errorf(`unknown key type %T`, rawKeyIf)
	}

	return nil
}

func (k *okpPrivateKey) FromRaw(rawKeyIf interface{}) error {
	switch rawKey := rawKeyIf.(type) {
	case ed25519.PrivateKey:
		k.d = rawKey.Seed()
		k.x = rawKey.Public().(ed25519.PublicKey)
		if err := k.Set(OKPCrvKey, jwa.Ed25519); err != nil {
			return errors.Wrap(err, `failed to set header`)
		}
	case x25519.PrivateKey:
		k.d = rawKey.Seed()
		k.x = rawKey.Public().(x25519.PublicKey)
		if err := k.Set(OKPCrvKey, jwa.X25519); err != nil {
			return errors.Wrap(err, `failed to set header`)
		}
	default:
		return errors.Errorf(`unknown key type %T`, rawKeyIf)
	}

	return nil
}

func buildOKPPublicKey(alg jwa.EllipticCurveAlgorithm, xbuf []byte) (interface{}, error) {
	switch alg {
	case jwa.Ed25519:
		return ed25519.PublicKey(xbuf), nil
	case jwa.X25519:
		return x25519.PublicKey(xbuf), nil
	default:
		return nil, errors.Errorf(`invalid curve algorithm %s`, alg)
	}
}

// Raw returns the EC-DSA public key represented by this JWK
func (k *okpPublicKey) Raw(v interface{}) error {
	pubk, err := buildOKPPublicKey(k.Crv(), k.x)
	if err != nil {
		return errors.Wrap(err, `failed to build public key`)
	}

	return blackmagic.AssignIfCompatible(v, pubk)
}

func buildOKPPrivateKey(alg jwa.EllipticCurveAlgorithm, xbuf []byte, dbuf []byte) (interface{}, error) {
	switch alg {
	case jwa.Ed25519:
		ret := ed25519.NewKeyFromSeed(dbuf)
		if !bytes.Equal(xbuf, ret.Public().(ed25519.PublicKey)) {
			return nil, errors.Errorf(`invalid x value given d value`)
		}
		return ret, nil
	case jwa.X25519:
		ret, err := x25519.NewKeyFromSeed(dbuf)
		if err != nil {
			return nil, errors.Wrap(err, `unable to construct x25519 private key from seed`)
		}
		if !bytes.Equal(xbuf, ret.Public().(x25519.PublicKey)) {
			return nil, errors.Errorf(`invalid x value given d value`)
		}
		return ret, nil
	default:
		return nil, errors.Errorf(`invalid curve algorithm %s`, alg)
	}
}

func (k *okpPrivateKey) Raw(v interface{}) error {
	privk, err := buildOKPPrivateKey(k.Crv(), k.x, k.d)
	if err != nil {
		return errors.Wrap(err, `failed to build public key`)
	}

	return blackmagic.AssignIfCompatible(v, privk)
}

func (k *okpPrivateKey) PublicKey() (OKPPublicKey, error) {
	newKey := NewOKPPublicKey()
	switch k.Crv() {
	case jwa.Ed25519:
		if err := newKey.FromRaw(ed25519.PublicKey(k.x)); err != nil {
			return nil, errors.Wrap(err, `failed to initialize OKPPublicKey`)
		}
	case jwa.X25519:
		if err := newKey.FromRaw(x25519.PublicKey(k.x)); err != nil {
			return nil, errors.Wrap(err, `failed to initialize OKPPublicKey`)
		}
	default:
		return nil, errors.Errorf(`invalid curve algorithm %s`, k.Crv())
	}
	return newKey, nil
}

func okpThumbprint(hash crypto.Hash, crv, x string) []byte {
	h := hash.New()
	fmt.Fprint(h, `{"crv":"`)
	fmt.Fprint(h, crv)
	fmt.Fprint(h, `","kty":"OKP","x":"`)
	fmt.Fprint(h, x)
	fmt.Fprint(h, `"}`)
	return h.Sum(nil)
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638 / 8037
func (k okpPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	return okpThumbprint(
		hash,
		k.Crv().String(),
		base64.EncodeToString(k.x),
	), nil
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638 / 8037
func (k okpPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	return okpThumbprint(
		hash,
		k.Crv().String(),
		base64.EncodeToString(k.x),
	), nil
}
