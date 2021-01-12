package traefik_jwt_middleware

import "testing"

func TestPlugin(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTAwIiwidXNlcl9uYW1lIjoidGVzdCIsImVtYWlsIjoidGVzdEB0ZXN0LmNvbSIsInVzZXJfbGV2ZWwiOjAsInN0b3JlcyI6bnVsbCwid29vX3N0b3JlcyI6bnVsbCwiY3JlYXRlZF9hdCI6MTYxMDQzMDIyNCwiZXhwIjoxNjEwNDMwNTI0fQ.gptBSikSl_kW3tTXWWsZsvQ0IdsTNV5f4gQMtuV7jfA"
	key := "{\"kty\":\"oct\",\"use\":\"sig\",\"kid\":\"default\",\"k\":\"MWNhZjc2YV4xJWE0QjU2NTYqNCZmYzIoYjAxMzVjMmU=\",\"alg\":\"HS256\"}"

	payload, err := verifyJWT(token, key)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(payload)
}