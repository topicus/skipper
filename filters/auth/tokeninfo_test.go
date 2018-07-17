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

func TestOAuth2Tokeninfo(t *testing.T) {
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
		authType: OAuthTokeninfoAnyScopeName,
		expected: http.StatusNotFound,
	}, {
		msg:         "invalid token",
		authType:    OAuthTokeninfoAnyScopeName,
		authBaseURL: testAuthPath,
		hasAuth:     true,
		auth:        "invalid-token",
		expected:    http.StatusNotFound,
	}, {
		msg:         "invalid scope",
		authType:    OAuthTokeninfoAnyScopeName,
		authBaseURL: testAuthPath,
		args:        []interface{}{"not-matching-scope"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
	}, {
		msg:         "oauthTokeninfoAnyScope: valid token, one valid scope",
		authType:    OAuthTokeninfoAnyScopeName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testScope},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusOK,
	}, {
		msg:         "OAuthTokeninfoAnyScopeName: valid token, one valid scope, one invalid scope",
		authType:    OAuthTokeninfoAnyScopeName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testScope, "other-scope"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusOK,
	}, {
		msg:         "oauthTokeninfoAllScope(): valid token, valid scopes",
		authType:    OAuthTokeninfoAllScopeName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testScope, testScope2, testScope3},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusOK,
	}, {
		msg:         "oauthTokeninfoAllScope(): valid token, one valid scope, one invalid scope",
		authType:    OAuthTokeninfoAllScopeName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testScope, "other-scope"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
	}, {
		msg:         "anyKV(): invalid key",
		authType:    OAuthTokeninfoAnyKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{"not-matching-scope"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusNotFound,
	}, {
		msg:         "anyKV(): valid token, one valid key, wrong value",
		authType:    OAuthTokeninfoAnyKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testKey, "other-value"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
	}, {
		msg:         "anyKV(): valid token, one valid key value pair",
		authType:    OAuthTokeninfoAnyKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testKey, testValue},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusOK,
	}, {
		msg:         "anyKV(): valid token, one valid kv, multiple key value pairs1",
		authType:    OAuthTokeninfoAnyKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testKey, testValue, "wrongKey", "wrongValue"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusOK,
	}, {
		msg:         "anyKV(): valid token, one valid kv, multiple key value pairs2",
		authType:    OAuthTokeninfoAnyKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{"wrongKey", "wrongValue", testKey, testValue},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusOK,
	}, {
		msg:         "allKV(): invalid key",
		authType:    OAuthTokeninfoAllKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{"not-matching-scope"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusNotFound,
	}, {
		msg:         "allKV(): valid token, one valid key, wrong value",
		authType:    OAuthTokeninfoAllKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testKey, "other-value"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
	}, {
		msg:         "allKV(): valid token, one valid key value pair",
		authType:    OAuthTokeninfoAllKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testKey, testValue},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusOK,
	}, {
		msg:         "allKV(): valid token, one valid key value pair, check realm",
		authType:    OAuthTokeninfoAllKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testRealmKey, testRealm, testKey, testValue},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusOK,
	}, {
		msg:         "allKV(): valid token, valid key value pairs",
		authType:    OAuthTokeninfoAllKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testKey, testValue, testKey, testValue},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusOK,
	}, {
		msg:         "allKV(): valid token, one valid kv, multiple key value pairs1",
		authType:    OAuthTokeninfoAllKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{testKey, testValue, "wrongKey", "wrongValue"},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
	}, {
		msg:         "allKV(): valid token, one valid kv, multiple key value pairs2",
		authType:    OAuthTokeninfoAllKVName,
		authBaseURL: testAuthPath,
		args:        []interface{}{"wrongKey", "wrongValue", testKey, testValue},
		hasAuth:     true,
		auth:        testToken,
		expected:    http.StatusUnauthorized,
	}} {
		t.Run(ti.msg, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {}))

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

			var s filters.Spec
			args := []interface{}{}
			u := authServer.URL + ti.authBaseURL
			switch ti.authType {
			case OAuthTokeninfoAnyScopeName:
				s = NewOAuthTokeninfoAnyScope(u)
			case OAuthTokeninfoAllScopeName:
				s = NewOAuthTokeninfoAllScope(u)
			case OAuthTokeninfoAnyKVName:
				s = NewOAuthTokeninfoAnyKV(u)
			case OAuthTokeninfoAllKVName:
				s = NewOAuthTokeninfoAllKV(u)
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
			for _, name := range []string{"query", "header"} {
				if ti.hasAuth && name == "query" {
					q := reqURL.Query()
					q.Add(accessTokenKey, ti.auth)
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
					t.Errorf("auth filter failed got=%d, expected=%d, route=%s", rsp.StatusCode, ti.expected, r)
					buf := make([]byte, rsp.ContentLength)
					rsp.Body.Read(buf)
				}
			}
		})
	}
}
