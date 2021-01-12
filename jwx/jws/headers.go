package jws

import (
	"context"
	"github.com/whlanuo/traefik-jwt-middleware/iter/mapiter"
	iter2 "github.com/whlanuo/traefik-jwt-middleware/jwx/internal/iter"
)

// Iterate returns a channel that successively returns all the
// header name and values.
func (h *stdHeaders) Iterate(ctx context.Context) Iterator {
	ch := make(chan *HeaderPair)
	go h.iterate(ctx, ch)
	return mapiter.New(ch)
}

func (h *stdHeaders) Walk(ctx context.Context, visitor Visitor) error {
	return iter2.WalkMap(ctx, h, visitor)
}

func (h *stdHeaders) AsMap(ctx context.Context) (map[string]interface{}, error) {
	return iter2.AsMap(ctx, h)
}
