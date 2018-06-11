package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/proxy/proxytest"
)

var testOidcConfig *OpenIDConfig = &OpenIDConfig{
	Issuer:                            "https://identity.example.com",
	AuthorizationEndpoint:             "https://identity.example.com/oauth2/authorize",
	TokenEndpoint:                     "https://identity.example.com/oauth2/token",
	UserinfoEndpoint:                  "https://identity.example.com/oauth2/userinfo",
	RevocationEndpoint:                "https://identity.example.com/oauth2/revoke",
	JwksURI:                           "https://identity.example.com/.well-known/jwk_uris",
	RegistrationEndpoint:              "https://identity.example.com/oauth2/register",
	IntrospectionEndpoint:             "https://identity.example.com/oauth2/introspection",
	ResponseTypesSupported:            []string{"code", "token", "code token"},
	SubjectTypesSupported:             []string{"public"},
	IDTokenSigningAlgValuesSupported:  []string{"RS256", "ES512", "PS384"},
	TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
	ClaimsSupported:                   []string{"sub", "name", "email", "azp", "iss", "exp", "iat", "https://identity.example.com/token", "https://identity.example.com/realm", "https://identity.example.com/bp", "https://identity.example.com/privileges"},
	ScopesSupported:                   []string{"openid", "email"},
	CodeChallengeMethodsSupported:     []string{"plain", "S256"},
}

func TestOAuth2Tokenintrospection(t *testing.T) {
	for _, ti := range []struct {
		msg         string
		authType    string
		authBaseURL string
		args        []interface{}
		hasAuth     bool
		auth        string
		expected    int
	}{{
		msg:      "uninitialized filter, no authorization header, scope check",
		authType: OAuthTokenintrospectionAnyClaimsName,
		expected: http.StatusNotFound,
	}, {
		msg:         "invalid token",
		authType:    OAuthTokenintrospectionAnyClaimsName,
		authBaseURL: testAuthPath,
		hasAuth:     true,
		auth:        "invalid-token",
		expected:    http.StatusNotFound,
	}, {
		msg:         "invalid scope",
		authType:    OAuthTokenintrospectionAnyClaimsName,
		authBaseURL: testAuthPath,
		args:        []interface{}{"not-matching-scope"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
		// }, {
		// 	msg:         "oauthTokenintrospectionAnyClaim: valid token, one valid scope",
		// 	authType:    OAuthTokenintrospectionAnyClaimsName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{testScope},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusOK,
		// }, {
		// 	msg:         "OAuthTokenintrospectionAnyClaimsName: valid token, one valid scope, one invalid scope",
		// 	authType:    OAuthTokenintrospectionAnyClaimsName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{testScope, "other-scope"},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusOK,
		// }, {
		// 	msg:         "oauthTokenintrospectionAllClaim(): valid token, valid scopes",
		// 	authType:    OAuthTokenintrospectionAllClaimsName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{testScope, testScope2, testScope3},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusOK,
		// }, {
		// 	msg:         "oauthTokenintrospectionAllClaim(): valid token, one valid scope, one invalid scope",
		// 	authType:    OAuthTokenintrospectionAllClaimsName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{testScope, "other-scope"},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusUnauthorized,
	}, {
		msg:         "anyKV(): invalid key",
		authType:    OAuthTokenintrospectionAnyKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{"not-matching-scope"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusNotFound,
	}, {
		msg:         "anyKV(): valid token, one valid key, wrong value",
		authType:    OAuthTokenintrospectionAnyKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testKey, "other-value"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
		// }, {
		// 	msg:         "anyKV(): valid token, one valid key value pair",
		// 	authType:    OAuthTokenintrospectionAnyKVName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{testKey, testValue},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusOK,
		// }, {
		// 	msg:         "anyKV(): valid token, one valid kv, multiple key value pairs1",
		// 	authType:    OAuthTokenintrospectionAnyKVName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{testKey, testValue, "wrongKey", "wrongValue"},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusOK,
		// }, {
		// 	msg:         "anyKV(): valid token, one valid kv, multiple key value pairs2",
		// 	authType:    OAuthTokenintrospectionAnyKVName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{"wrongKey", "wrongValue", testKey, testValue},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusOK,
	}, {
		msg:         "allKV(): invalid key",
		authType:    OAuthTokenintrospectionAllKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{"not-matching-scope"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusNotFound,
	}, {
		msg:         "allKV(): valid token, one valid key, wrong value",
		authType:    OAuthTokenintrospectionAllKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testKey, "other-value"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
		// }, {
		// 	msg:         "allKV(): valid token, one valid key value pair",
		// 	authType:    OAuthTokenintrospectionAllKVName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{testKey, testValue},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusOK,
		// }, {
		// 	msg:         "allKV(): valid token, one valid key value pair, check realm",
		// 	authType:    OAuthTokenintrospectionAllKVName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{testRealmKey, testRealm, testKey, testValue},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusOK,
		// }, {
		// 	msg:         "allKV(): valid token, valid key value pairs",
		// 	authType:    OAuthTokenintrospectionAllKVName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{testKey, testValue, testKey, testValue},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusOK,
	}, {
		msg:         "allKV(): valid token, one valid kv, multiple key value pairs1",
		authType:    OAuthTokenintrospectionAllKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testKey, testValue, "wrongKey", "wrongValue"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
	}, {
		msg:         "allKV(): valid token, one valid kv, multiple key value pairs2",
		authType:    OAuthTokenintrospectionAllKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{"wrongKey", "wrongValue", testKey, testValue},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
	}} {
		t.Run(ti.msg, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

			authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != testAuthPath {
					w.WriteHeader(http.StatusNotFound)
					return
				}

				token, err := getToken(r)
				if err != nil || token != testToken {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				d := map[string]interface{}{
					"uid":        testUID,
					testRealmKey: testRealm,
					"scope":      []string{testScope, testScope2, testScope3}}

				e := json.NewEncoder(w)
				err = e.Encode(&d)
				if err != nil {
					t.Error(err)
				}
			}))
			t.Logf("listen authserver: %v, backend: %v", authServer.Listener.Addr(), backend.Listener.Addr())
			defer authServer.Close()

			var s filters.Spec
			args := []interface{}{}

			switch ti.authType {
			case OAuthTokenintrospectionAnyClaimsName:
				s = NewOAuthTokenintrospectionAnyClaims(testOidcConfig)
			case OAuthTokenintrospectionAllClaimsName:
				s = NewOAuthTokenintrospectionAllClaims(testOidcConfig)
			case OAuthTokenintrospectionAnyKVName:
				s = NewOAuthTokenintrospectionAnyKV(testOidcConfig)
			case OAuthTokenintrospectionAllKVName:
				s = NewOAuthTokenintrospectionAllKV(testOidcConfig)
			}

			args = append(args, ti.args...)
			fr := make(filters.Registry)
			fr.Register(s)
			r := &eskip.Route{Filters: []*eskip.Filter{{Name: s.Name(), Args: args}}, Backend: backend.URL}

			proxy := proxytest.New(fr, r)
			reqURL, err := url.Parse(proxy.URL)
			if err != nil {
				t.Errorf("Failed to parse url %s: %v", proxy.URL, err)
			}

			// test accessToken in querystring and header
			for _, name := range []string{"query"} { //, "header"} {
				if ti.hasAuth && name == "query" {
					q := reqURL.Query()
					q.Add(accessTokenQueryKey, ti.auth)
					reqURL.RawQuery = q.Encode()
				}

				req, err := http.NewRequest("GET", reqURL.String(), nil)
				if err != nil {
					t.Error(err)
					return
				}

				if ti.hasAuth && name == "header" {
					req.Header.Set(authHeaderName, "Bearer "+url.QueryEscape(ti.auth))
				}

				rsp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Error(err)
				}

				defer rsp.Body.Close()

				if rsp.StatusCode != ti.expected {
					t.Errorf("name=%s, filter(%s) failed got=%d, expected=%d, route=%s", name, s.Name(), rsp.StatusCode, ti.expected, r)
					buf := make([]byte, rsp.ContentLength)
					rsp.Body.Read(buf)
				}
			}
		})
	}
}
