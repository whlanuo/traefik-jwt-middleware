package jwk

import (
	"crypto"
	"fmt"
	base642 "github.com/whlanuo/traefik-jwt-middleware/jwx/internal/base64"
	blackmagic2 "github.com/whlanuo/traefik-jwt-middleware/jwx/internal/blackmagic"

	"github.com/whlanuo/traefik-jwt-middleware/errors"
)

func NewSymmetricKey() SymmetricKey {
	return newSymmetricKey()
}

func newSymmetricKey() *symmetricKey {
	return &symmetricKey{
		privateParams: make(map[string]interface{}),
	}
}

func (k *symmetricKey) FromRaw(rawKey []byte) error {
	if len(rawKey) == 0 {
		return errors.New(`non-empty []byte key required`)
	}

	k.octets = rawKey

	return nil
}

// Raw returns the octets for this symmetric key.
// Since this is a symmetric key, this just calls Octets
func (k symmetricKey) Raw(v interface{}) error {
	return blackmagic2.AssignIfCompatible(v, k.octets)
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (k symmetricKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	var octets []byte
	if err := k.Raw(&octets); err != nil {
		return nil, errors.Wrap(err, `failed to materialize symmetric key`)
	}

	h := hash.New()
	fmt.Fprint(h, `{"k":"`)
	fmt.Fprint(h, base642.EncodeToString(octets))
	fmt.Fprint(h, `","kty":"oct"}`)
	return h.Sum(nil), nil
}
