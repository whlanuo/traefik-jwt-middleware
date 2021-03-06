package jwk

import "github.com/whlanuo/traefik-jwt-middleware/errors"

func (k KeyUsageType) String() string {
	return string(k)
}

func (k *KeyUsageType) Accept(v interface{}) error {
	switch v := v.(type) {
	case KeyUsageType:
		switch v {
		case ForSignature, ForEncryption:
			*k = v
		default:
			return errors.Errorf("invalid key usage type %s", v)
		}
	case string:
		switch v {
		case ForSignature.String(), ForEncryption.String():
			*k = KeyUsageType(v)
		default:
			return errors.Errorf("invalid key usage type %s", v)
		}
	}

	return errors.Errorf("invalid value for key usage tyupe %s", v)
}
