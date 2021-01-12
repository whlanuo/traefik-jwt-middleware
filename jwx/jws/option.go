package jws

import (
	"github.com/whlanuo/traefik-jwt-middleware/jwx/jws/sign"
	"github.com/whlanuo/traefik-jwt-middleware/option"
)

type Option = option.Interface

type identPayloadSigner struct{}
type identHeaders struct{}

func WithSigner(signer sign.Signer, key interface{}, public, protected Headers) Option {
	return option.New(identPayloadSigner{}, &payloadSigner{
		signer:    signer,
		key:       key,
		protected: protected,
		public:    public,
	})
}

func WithHeaders(h Headers) Option {
	return option.New(identHeaders{}, h)
}
