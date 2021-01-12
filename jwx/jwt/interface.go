package jwt

import (
	"github.com/whlanuo/traefik-jwt-middleware/iter/mapiter"
	iter2 "github.com/whlanuo/traefik-jwt-middleware/jwx/internal/iter"
)

type ClaimPair = mapiter.Pair
type Iterator = mapiter.Iterator
type Visitor = iter2.MapVisitor
type VisitorFunc iter2.MapVisitorFunc
