//go:generate go run internal/cmd/gentoken/main.go

// Package jwt implements JSON Web Tokens as described in https://tools.ietf.org/html/rfc7519
package jwt

import (
	"bytes"
	json2 "github.com/whlanuo/traefik-jwt-middleware/jwx/internal/json"
	jwa2 "github.com/whlanuo/traefik-jwt-middleware/jwx/jwa"
	jwk2 "github.com/whlanuo/traefik-jwt-middleware/jwx/jwk"
	jws2 "github.com/whlanuo/traefik-jwt-middleware/jwx/jws"
	"io"
	"io/ioutil"
	"strings"

	"github.com/whlanuo/traefik-jwt-middleware/errors"
)

// ParseString calls Parse with the given string
func ParseString(s string, options ...Option) (Token, error) {
	return Parse(strings.NewReader(s), options...)
}

// ParseBytes calls Parse with the given byte sequence
func ParseBytes(s []byte, options ...Option) (Token, error) {
	return Parse(bytes.NewReader(s), options...)
}

// Parse parses the JWT token payload and creates a new `jwt.Token` object.
// The token must be encoded in either JSON format or compact format.
//
// If the token is signed and you want to verify the payload matches the signature,
// you must pass the jwt.WithVerify(alg, key) or jwt.WithKeySet(*jwk.Set) option.
// If you do not specify these parameters, no verification will be performed.
//
// If you also want to assert the validity of the JWT itself (i.e. expiration
// and such), use the `Valid()` function on the returned token, or pass the
// `WithValidation(true)` option. Validation options can also be passed to
// `Parse`
//
// This function takes both ParseOption and Validate Option types:
// ParseOptions control the parsing behavior, and ValidateOptions are
// passed to `Validate()` when `jwt.WithValidate` is specified.
func Parse(src io.Reader, options ...Option) (Token, error) {
	var params VerifyParameters
	var keyset *jwk2.Set
	var useDefault bool
	var token Token
	var validate bool
	for _, o := range options {
		switch o.Ident() {
		case identVerify{}:
			params = o.Value().(VerifyParameters)
		case identKeySet{}:
			keyset = o.Value().(*jwk2.Set)
		case identToken{}:
			token = o.Value().(Token)
		case identDefault{}:
			useDefault = o.Value().(bool)
		case identValidate{}:
			validate = o.Value().(bool)
		}
	}

	// We're going to need the raw bytes regardless. Read it.
	data, err := ioutil.ReadAll(src)
	if err != nil {
		return nil, errors.Wrap(err, `failed to read from token data source`)
	}

	// If with matching kid is true, then look for the corresponding key in the
	// given key set, by matching the "kid" key
	if keyset != nil {
		alg, key, err := lookupMatchingKey(data, keyset, useDefault)
		if err != nil {
			return nil, errors.Wrap(err, `failed to find matching key for verification`)
		}
		return parse(token, data, true, alg, key, validate, options...)
	}

	if params != nil {
		return parse(token, data, true, params.Algorithm(), params.Key(), validate, options...)
	}

	return parse(token, data, false, "", nil, validate, options...)
}

// verify parameter exists to make sure that we don't accidentally skip
// over verification just because alg == ""  or key == nil or something.
func parse(token Token, data []byte, verify bool, alg jwa2.SignatureAlgorithm, key interface{}, validate bool, options ...Option) (Token, error) {
	var payload []byte
	if verify {
		v, err := jws2.Verify(data, alg, key)
		if err != nil {
			return nil, errors.Wrap(err, `failed to verify jws signature`)
		}
		payload = v
	} else {
		// TODO: seems slightly wasteful to use ioutil.ReadAll and then
		// create a new reader again. jws API kind of forces us to use
		// readers, but perhaps this can be fixed in future releases
		m, err := jws2.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, errors.Wrap(err, `invalid jws message`)
		}
		payload = m.Payload()

		// If JWS parse did not produce a full JWS message but also
		// there were no errors, assume that this is an unsigned, raw
		// JWT message
		if len(payload) == 0 && len(m.Signatures()) == 0 {
			payload = data
		}
	}

	if token == nil {
		token = New()
	}
	if err := json2.Unmarshal(payload, token); err != nil {
		return nil, errors.Wrap(err, `failed to parse token`)
	}

	if validate {
		var vopts []ValidateOption
		for _, o := range options {
			if v, ok := o.(ValidateOption); ok {
				vopts = append(vopts, v)
			}
		}

		if err := Validate(token, vopts...); err != nil {
			return nil, err
		}
	}
	return token, nil
}

func lookupMatchingKey(data []byte, keyset *jwk2.Set, useDefault bool) (jwa2.SignatureAlgorithm, interface{}, error) {
	msg, err := jws2.Parse(bytes.NewReader(data))
	if err != nil {
		return "", nil, errors.Wrap(err, `failed to parse token data`)
	}

	headers := msg.Signatures()[0].ProtectedHeaders()
	kid := headers.KeyID()
	if kid == "" {
		if !useDefault {
			return "", nil, errors.New(`failed to find matching key: no key ID specified in token`)
		} else if useDefault && keyset.Len() > 1 {
			return "", nil, errors.New(`failed to find matching key: no key ID specified in token but multiple in key set`)
		}
	}

	var keys []jwk2.Key
	if kid == "" {
		keys = keyset.Keys
	} else {
		keys = keyset.LookupKeyID(kid)
	}
	if len(keys) == 0 {
		return "", nil, errors.Errorf(`failed to find matching key for key ID %#v in key set`, kid)
	}

	var rawKey interface{}
	if err := keys[0].Raw(&rawKey); err != nil {
		return "", nil, errors.Wrapf(err, `failed to construct raw key from keyset (key ID=%#v)`, kid)
	}

	return headers.Algorithm(), rawKey, nil
}

// ParseVerify is marked to be deprecated. Please use jwt.Parse
// with appropriate options instead.
//
// ParseVerify a function that is similar to Parse(), but does not
// allow for parsing without signature verification parameters.
//
// If you want to provide a *jwk.Set and allow the library to automatically
// choose the key to use using the Key IDs, use the jwt.WithKeySet option
// along with the jwt.Parse function.
func ParseVerify(src io.Reader, alg jwa2.SignatureAlgorithm, key interface{}) (Token, error) {
	return Parse(src, WithVerify(alg, key))
}

// Sign is a convenience function to create a signed JWT token serialized in
// compact form.
//
// It accepts either a raw key (e.g. rsa.PrivateKey, ecdsa.PrivateKey, etc)
// or a jwk.Key, and the name of the algorithm that should be used to sign
// the token.
//
// If the key is a jwk.Key and the key contains a key ID (`kid` field),
// then it is added to the protected header generated by the signature
//
// The algorithm specified in the `alg` parameter must be able to support
// the type of key you provided, otherwise an error is returned.
//
// The protected header will also automatically have the `typ` field set
// to the literal value `JWT`.
func Sign(t Token, alg jwa2.SignatureAlgorithm, key interface{}, options ...Option) ([]byte, error) {
	var hdr jws2.Headers
	for _, o := range options {
		switch o.Ident() {
		case identHeaders{}:
			hdr = o.Value().(jws2.Headers)
		}
	}

	buf, err := json2.Marshal(t)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal token`)
	}

	if hdr == nil {
		hdr = jws2.NewHeaders()
	}

	if err := hdr.Set(`typ`, `JWT`); err != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}
	sign, err := jws2.Sign(buf, alg, key, jws2.WithHeaders(hdr))
	if err != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}

	return sign, nil
}
