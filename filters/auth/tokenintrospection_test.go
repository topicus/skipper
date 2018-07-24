package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
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

var (
	validClaim1      = "email"
	validClaim1Value = "jdoe@example.com"
	validClaim2      = "name"
	validClaim2Value = "Jane Doe"
)

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
		msg:         "unsupported claim",
		authType:    OAuthTokenintrospectionAnyClaimsName,
		authBaseURL: testAuthPath,
		args:        []interface{}{"unsupported-claim"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusNotFound,
	}, {
		msg:         "invalid claim",
		authType:    OAuthTokenintrospectionAnyClaimsName,
		authBaseURL: testAuthPath,
		args:        []interface{}{validClaim1, validClaim2},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
	}, {
		msg:         "oauthTokenintrospectionAnyClaim: valid token, one valid claim",
		authType:    OAuthTokenintrospectionAnyClaimsName,
		authBaseURL: testAuthPath,
		args:        []interface{}{validClaim1, validClaim2},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusOK,
	}, {
		msg:         "OAuthTokenintrospectionAnyClaimsName: valid token, one valid claim, one invalid claim value",
		authType:    OAuthTokenintrospectionAnyClaimsName,
		authBaseURL: testAuthPath,
		args:        []interface{}{validClaim1, validClaim1Value, validClaim2, "invalidClaimValue"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusOK,
	}, {
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
		// }, {
		// 	msg:         "anyKV(): invalid key",
		// 	authType:    OAuthTokenintrospectionAnyKVName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{"not-matching-scope"},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusNotFound,
		// }, {
		// 	msg:         "anyKV(): valid token, one valid key, wrong value",
		// 	authType:    OAuthTokenintrospectionAnyKVName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{testKey, "other-value"},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusUnauthorized,
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
		// }, {
		// 	msg:         "allKV(): invalid key",
		// 	authType:    OAuthTokenintrospectionAllKVName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{"not-matching-scope"},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusNotFound,
		// }, {
		// 	msg:         "allKV(): valid token, one valid key, wrong value",
		// 	authType:    OAuthTokenintrospectionAllKVName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{testKey, "other-value"},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusUnauthorized,
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
		// }, {
		// 	msg:         "allKV(): valid token, one valid kv, multiple key value pairs1",
		// 	authType:    OAuthTokenintrospectionAllKVName,
		// 	authBaseURL: testAuthPath,
		// 	args:        []interface{}{testKey, testValue, "wrongKey", "wrongValue"},
		// 	hasAuth:     true,
		// 	auth:        testToken,
		// 	expected:    http.StatusUnauthorized,
		// }, {
		msg:         "allKV(): valid token, one valid kv, multiple key value pairs2",
		authType:    OAuthTokenintrospectionAllKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{"wrongKey", "wrongValue", testKey, testValue},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
	}} {
		t.Run(ti.msg, func(t *testing.T) {
			if ti.msg == "" {
				t.Fatalf("unknown ti: %+v", ti)
			}
			backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

			authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Log("authServer got a request")
				if r.Method != "POST" {
					w.WriteHeader(489) //(http.StatusNotFound)
					return
				}

				if r.URL.Path != testAuthPath {
					t.Logf("r.URL.Path: %s != %s :testAuthPath", r.URL.Path, testAuthPath)
					w.WriteHeader(488) //(http.StatusNotFound)
					return
				}

				t.Logf("getToken from request: formValue: %v, authheader: %v", r.FormValue(accessTokenKey), r.Header.Get("Authorization"))
				token, err := getToken(r)
				if err != nil || token != testToken {
					t.Logf("token: %s == %s :testToken", token, testToken)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				t.Log("got a valid token")
				d := tokenIntrospectionInfo{
					"uid":        testUID,
					testRealmKey: testRealm,
					//"scope":      []string{testScope, testScope2, testScope3},
					"claims": map[string]string{
						validClaim1: validClaim1Value,
						validClaim2: validClaim2Value,
					},
					"sub":    "testSub",
					"active": true,
				}

				e := json.NewEncoder(w)
				err = e.Encode(&d)
				if err != nil && err != io.EOF {
					t.Errorf("Failed to json encode: %v", err)
				}
				t.Log("authserver end")
			}))

			testOidcConfig.IntrospectionEndpoint = "http://" + authServer.Listener.Addr().String() + testAuthPath
			t.Logf("testOidcConfig.IntrospectionEndpoint: %s", testOidcConfig.IntrospectionEndpoint)
			defer authServer.Close()

			var spec filters.Spec
			args := []interface{}{}

			switch ti.authType {
			case OAuthTokenintrospectionAnyClaimsName:
				spec = NewOAuthTokenintrospectionAnyClaims(testOidcConfig)
			case OAuthTokenintrospectionAllClaimsName:
				spec = NewOAuthTokenintrospectionAllClaims(testOidcConfig)
			case OAuthTokenintrospectionAnyKVName:
				spec = NewOAuthTokenintrospectionAnyKV(testOidcConfig)
			case OAuthTokenintrospectionAllKVName:
				spec = NewOAuthTokenintrospectionAllKV(testOidcConfig)
			default:
				t.Fatalf("FATAL: authType '%s' not supported", ti.authType)
			}

			args = append(args, ti.args...)
			fr := make(filters.Registry)
			fr.Register(spec)
			r := &eskip.Route{Filters: []*eskip.Filter{{Name: spec.Name(), Args: args}}, Backend: backend.URL}

			proxy := proxytest.New(fr, r)

			reqURL, err := url.Parse(proxy.URL)
			if err != nil {
				t.Errorf("Failed to parse url %s: %v", proxy.URL, err)
			}

			// test accessToken in form value and header
			for _, name := range []string{"form"} { //, "header"} {
				formdata := url.Values{}
				if ti.hasAuth && name == "form" {
					formdata.Add(accessTokenKey, ti.auth)
				}
				body := strings.NewReader(formdata.Encode())

				req, err := http.NewRequest("POST", reqURL.String(), body)
				if err != nil {
					t.Errorf("failed to create request %v", err)
					return
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				if ti.hasAuth && name == "header" {
					req.Header.Set(authHeaderName, "Bearer "+url.QueryEscape(ti.auth))
				}

				rsp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Errorf("failed to get response: %v", err)
				}
				log.Infof("rsp: %#v", rsp)

				defer rsp.Body.Close()

				if rsp.StatusCode != ti.expected {
					t.Errorf("name=%s, filter(%s) failed got=%d, expected=%d, route=%s", name, spec.Name(), rsp.StatusCode, ti.expected, r)
					buf := make([]byte, rsp.ContentLength)
					n, err := rsp.Body.Read(buf)
					t.Logf("response buffer(%d) (%v): %s", n, err, buf)
				}
			}
		})
	}
}

func Test_validateAnyClaims(t *testing.T) {
	claims := []string{"email", "name"}
	claimsPartialOverlapping := []string{"email", "name", "missing"}
	info := tokenIntrospectionInfo{
		"/realm": "/immortals",
		"claims": map[string]interface{}{
			"email": "jdoe@example.com",
			"name":  "Jane Doe",
			"uid":   "jdoe",
		},
	}

	for _, ti := range []struct {
		msg      string
		claims   []string
		info     tokenIntrospectionInfo
		expected bool
	}{{
		msg:      "validate any, noclaims configured, got no claims",
		claims:   []string{},
		info:     tokenIntrospectionInfo{},
		expected: false,
	}, {
		msg:      "validate any, noclaims configured, got claims",
		claims:   []string{},
		info:     info,
		expected: false,
	}, {
		msg:      "validate any, claims configured, got no claims",
		claims:   claims,
		info:     tokenIntrospectionInfo{},
		expected: false,
	}, {
		msg:      "validate any, claims configured, got not enough claims",
		claims:   claimsPartialOverlapping,
		info:     info,
		expected: true,
	}, {
		msg:      "validate any, claims configured, got claims",
		claims:   claims,
		info:     info,
		expected: true,
	}} {
		t.Run(ti.msg, func(t *testing.T) {
			if ti.msg == "" {
				t.Fatalf("unknown ti: %+v", ti)
			}

			f := &tokenintrospectFilter{claims: ti.claims}
			if f.validateAnyClaims(ti.info) != ti.expected {
				t.Error("failed to validate any claims")
			}

		})
	}
}

func Test_validateAllClaims(t *testing.T) {
	claims := []string{"email", "name"}
	claimsPartialOverlapping := []string{"email", "name", "missing"}
	info := tokenIntrospectionInfo{
		"/realm": "/immortals",
		"claims": map[string]interface{}{
			"email": "jdoe@example.com",
			"name":  "Jane Doe",
			"uid":   "jdoe",
		},
	}

	for _, ti := range []struct {
		msg      string
		claims   []string
		info     tokenIntrospectionInfo
		expected bool
	}{{
		msg:      "validate all, noclaims configured, got no claims",
		claims:   []string{},
		info:     tokenIntrospectionInfo{},
		expected: true,
	}, {
		msg:      "validate all, noclaims configured, got claims",
		claims:   []string{},
		info:     info,
		expected: true,
	}, {
		msg:      "validate all, claims configured, got no claims",
		claims:   claims,
		info:     tokenIntrospectionInfo{},
		expected: false,
	}, {
		msg:      "validate all, claims configured, got not enough claims",
		claims:   claimsPartialOverlapping,
		info:     info,
		expected: false,
	}, {
		msg:      "validate all, claims configured, got claims",
		claims:   claims,
		info:     info,
		expected: true,
	}} {
		t.Run(ti.msg, func(t *testing.T) {
			if ti.msg == "" {
				t.Fatalf("unknown ti: %+v", ti)
			}

			f := &tokenintrospectFilter{claims: ti.claims}
			if f.validateAllClaims(ti.info) != ti.expected {
				t.Error("failed to validate all claims")
			}

		})
	}
}
