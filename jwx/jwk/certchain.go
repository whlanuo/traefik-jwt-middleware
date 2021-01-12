package jwk

import (
	"crypto/x509"
	base642 "github.com/whlanuo/traefik-jwt-middleware/jwx/internal/base64"
	json2 "github.com/whlanuo/traefik-jwt-middleware/jwx/internal/json"

	"github.com/whlanuo/traefik-jwt-middleware/errors"
)

func (c CertificateChain) MarshalJSON() ([]byte, error) {
	certs := c.Get()
	encoded := make([]string, len(certs))
	for i := 0; i < len(certs); i++ {
		encoded[i] = base642.EncodeToStringStd(certs[i].Raw)
	}
	return json2.Marshal(encoded)
}

func (c *CertificateChain) UnmarshalJSON(buf []byte) error {
	var list []string
	if err := json2.Unmarshal(buf, &list); err != nil {
		return errors.Wrap(err, `failed to unmarshal JSON into []string`)
	}

	var tmp CertificateChain
	if err := tmp.Accept(list); err != nil {
		return err
	}

	*c = tmp
	return nil
}

func (c CertificateChain) Get() []*x509.Certificate {
	return c.certs
}

func (c *CertificateChain) Accept(v interface{}) error {
	var list []string

	switch x := v.(type) {
	case string:
		list = []string{x}
	case []interface{}:
		list = make([]string, len(x))
		for i, e := range x {
			if es, ok := e.(string); ok {
				list[i] = es
				continue
			}
			return errors.Errorf(`invalid list element type: expected string, got %T at element %d`, e, i)
		}
	case []string:
		list = x
	default:
		return errors.Errorf(`invalid tpe for CertificateChain: %T`, v)
	}

	certs := make([]*x509.Certificate, len(list))
	for i, e := range list {
		buf, err := base642.DecodeString(e)
		if err != nil {
			return errors.Wrap(err, `failed to base64 decode list element`)
		}
		cert, err := x509.ParseCertificate(buf)
		if err != nil {
			return errors.Wrap(err, `failed to parse certificate`)
		}
		certs[i] = cert
	}

	*c = CertificateChain{
		certs: certs,
	}
	return nil
}