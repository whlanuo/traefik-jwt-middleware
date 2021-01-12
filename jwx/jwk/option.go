package jwk

import (
	"crypto"
	"net/http"
	"time"

	"github.com/whlanuo/traefik-jwt-middleware/option"
)

type Option = option.Interface

type identHTTPClient struct{}
type identThumbprintHash struct{}
type identRefreshInterval struct{}
type identMinRefreshInterval struct{}
type identRefreshBackoff struct{}

// WithHTTPClient allows users to specify the "net/http".Client object that
// is used when fetching *jwk.Set objects.
//
// For historical reasons this method is also used in `jwk.Fetch*` functions,
// eventhough the return value is marked as an `AutoRefreshOption`
func WithHTTPClient(cl *http.Client) AutoRefreshOption {
	return &autoRefreshOption{
		option.New(identHTTPClient{}, cl),
	}
}

func WithThumbprintHash(h crypto.Hash) Option {
	return option.New(identThumbprintHash{}, h)
}

type autoRefreshOption struct {
	Option
}

func (aro *autoRefreshOption) autoRefreshOption() bool {
	return true
}

// WithRefreshInterval specifies the static interval between refreshes
// of *jwk.Set objects controlled by jwk.AutoRefresh.
//
// Providing this option overrides the adaptive token refreshing based
// on Cache-Control/Expires header (and jwk.WithMinRefreshInterval),
// and refreshes will *always* happen in this interval.
func WithRefreshInterval(d time.Duration) AutoRefreshOption {
	return &autoRefreshOption{
		option.New(identRefreshInterval{}, d),
	}
}

// WithMinRefreshInterval specifies the minimum refresh interval to be used
// when using AutoRefresh. This value is ONLY used if you did not specify
// a user-supplied static refresh interval via `WithRefreshInterval`.
//
// This value is used as a fallback value when tokens are refreshed.
//
// When we fetch the key from a remote URL, we first look at the max-age
// directive from Cache-Control response header. If this value is present,
// we compare the max-age value and the value specified by this option
// and take the larger one.
//
// Next we check for the Expires header, and similarly if the header is
// present, we compare it against the value specified by this option,
// and take the larger one.
//
// Finally, if neither of the above headers are present, we use the
// value specified by this option as the next refresh timing
//
// If unspecified, the minimum refresh interval is 1 hour
func WithMinRefreshInterval(d time.Duration) AutoRefreshOption {
	return &autoRefreshOption{
		option.New(identMinRefreshInterval{}, d),
	}
}
