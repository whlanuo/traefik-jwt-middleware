package traefik_jwt_middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

type Config struct {
	Secret          string `json:"secret,omitempty"`
	ProxyHeaderName string `json:"proxyHeaderName,omitempty"`
	AuthHeader      string `json:"authHeader,omitempty"`
	HeaderPrefix    string `json:"headerPrefix,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	if len(config.Secret) == 0 {
		config.Secret = "SECRET"
	}
	if len(config.ProxyHeaderName) == 0 {
		config.ProxyHeaderName = "injectedPayload"
	}
	if len(config.AuthHeader) == 0 {
		config.AuthHeader = "Authorization"
	}
	if len(config.HeaderPrefix) == 0 {
		config.HeaderPrefix = "Bearer"
	}

	return &JWT{
		next:            next,
		name:            name,
		secret:          config.Secret,
		proxyHeaderName: config.ProxyHeaderName,
		authHeader:      config.AuthHeader,
		headerPrefix:    config.HeaderPrefix,
	}, nil
}

type JWT struct {
	next            http.Handler
	name            string
	secret          string
	proxyHeaderName string
	authHeader      string
	headerPrefix    string
}

func (j *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	headerToken := req.Header.Get(j.authHeader)

	if len(headerToken) == 0 {
		http.Error(res, "Request error", http.StatusBadRequest)
		return
	}

	token, preprocessError := preprocessJWT(headerToken, j.headerPrefix)
	if preprocessError != nil {
		http.Error(res, "Request error", http.StatusBadRequest)
		return
	}

	tk, verificationError := verifyJWT(token, j.secret)
	if verificationError != nil {
		http.Error(res, "Not allowed", http.StatusUnauthorized)
		return
	}

	if tk != nil {
		// Inject header as proxypayload or configured name
		req.Header.Add(j.proxyHeaderName, token)
		fmt.Println(req.Header)
		j.next.ServeHTTP(res, req)
	} else {
		http.Error(res, "Not allowed", http.StatusUnauthorized)
	}
}

// verifyJWT Verifies jwt token with jwks
func verifyJWT(token string, jwks string) (*jwt.Token, error) {
	jwkSet, err := jwk.ParseString(jwks)
	if err != nil {
		return nil, err
	}

	tk, err := jwt.ParseString(token, jwt.WithKeySet(jwkSet), jwt.UseDefaultKey(true), jwt.WithClock(jwt.ClockFunc(time.Now)))
	if err != nil {
		return nil, err
	}

	return &tk, nil
}

// preprocessJWT Takes the request header string, strips prefix and whitespaces and returns a Token
func preprocessJWT(reqHeader string, prefix string) (string, error) {
	// fmt.Println("==> [processHeader] SplitAfter")
	// structuredHeader := strings.SplitAfter(reqHeader, "Bearer ")[1]
	cleanedString := strings.TrimPrefix(reqHeader, prefix)
	cleanedString = strings.TrimSpace(cleanedString)
	// fmt.Println("<== [processHeader] SplitAfter", cleanedString)

	return cleanedString, nil
}
