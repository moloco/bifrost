package handlers

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/grant"
	"github.com/maximhq/bifrost/framework/kvstore"
	"github.com/maximhq/bifrost/framework/logstore"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

type testWSHandlerStore struct {
	matcher         *lib.HeaderMatcher
	allowDirectKeys bool
}

func (s testWSHandlerStore) GetHeaderMatcher() *lib.HeaderMatcher {
	return s.matcher
}

func (s testWSHandlerStore) GetStreamChunkInterceptor() lib.StreamChunkInterceptor {
	return nil
}

func (s testWSHandlerStore) GetAsyncJobExecutor() *logstore.AsyncJobExecutor {
	return nil
}

func (s testWSHandlerStore) GetAsyncJobResultTTL() int {
	return 0
}

func (s testWSHandlerStore) GetKVStore() *kvstore.Store {
	return nil
}

func (s testWSHandlerStore) GetMCPHeaderCombinedAllowlist() schemas.WhiteList {
	return nil
}

func (s testWSHandlerStore) ShouldAllowPerRequestStorageOverride() bool { return false }
func (s testWSHandlerStore) ShouldAllowPerRequestRawOverride() bool     { return false }
func (s testWSHandlerStore) ShouldAllowDirectKeys() bool                { return s.allowDirectKeys }
func (s testWSHandlerStore) GetMCPExternalServerURL() string            { return "" }
func (s testWSHandlerStore) GetMCPExternalClientURL() string            { return "" }

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return false }

func TestResolveWSStreamIdleTimeoutUsesProviderOverride(t *testing.T) {
	cfg := &lib.Config{
		Providers: map[schemas.ModelProvider]configstore.ProviderConfig{
			schemas.OpenAI: {
				NetworkConfig: &schemas.NetworkConfig{StreamIdleTimeoutInSeconds: 7},
			},
		},
	}

	timeout := resolveWSStreamIdleTimeout(cfg, schemas.OpenAI)
	assert.Equal(t, 7*time.Second, timeout)
}

func TestResolveWSStreamIdleTimeoutFallsBackToDefault(t *testing.T) {
	timeout := resolveWSStreamIdleTimeout(&lib.Config{}, schemas.OpenAI)
	assert.Equal(t, time.Duration(schemas.DefaultStreamIdleTimeoutInSeconds)*time.Second, timeout)
}

func TestIsWSReadTimeout(t *testing.T) {
	assert.True(t, isWSReadTimeout(timeoutNetError{}))
	assert.False(t, isWSReadTimeout(net.UnknownNetworkError("unknown")))
	assert.False(t, isWSReadTimeout(errors.New("boom")))
	assert.False(t, isWSReadTimeout(nil))
}

func TestNewBifrostError(t *testing.T) {
	bifrostErr := newBifrostError(504, "upstream_timeout", "upstream websocket stream timed out")
	if bifrostErr == nil {
		t.Fatal("expected bifrost error, got nil")
	}
	if bifrostErr.StatusCode == nil || *bifrostErr.StatusCode != 504 {
		t.Fatalf("status code = %#v, want 504", bifrostErr.StatusCode)
	}
	if bifrostErr.Error == nil {
		t.Fatal("expected error field, got nil")
	}
	if bifrostErr.Error.Type == nil || *bifrostErr.Error.Type != "upstream_timeout" {
		t.Fatalf("error type = %#v, want upstream_timeout", bifrostErr.Error.Type)
	}
	if bifrostErr.Error.Message != "upstream websocket stream timed out" {
		t.Fatalf("error message = %q, want upstream websocket stream timed out", bifrostErr.Error.Message)
	}
}

func TestCreateBifrostContextFromAuth_BaggageSessionIDSetsGrouping(t *testing.T) {
	ctx, cancel := createBifrostContextFromAuth(testWSHandlerStore{}, &authHeaders{
		baggage: "foo=bar, session-id=rt-ws-123, baz=qux",
	})
	defer cancel()

	if got, _ := ctx.Value(schemas.BifrostContextKeyParentRequestID).(string); got != "rt-ws-123" {
		t.Fatalf("parent request id = %q, want %q", got, "rt-ws-123")
	}
}

// A connection settles its identity at upgrade the way an HTTP request does at conversion, so
// governance sees a settled request whether or not a key was presented.
func TestCreateBifrostContextFromAuth_SettlesIdentity(t *testing.T) {
	cases := map[string]struct {
		auth     *authHeaders
		wantKind string
		wantKey  string
	}{
		"no credential":       {auth: &authHeaders{}},
		"virtual key header":  {auth: &authHeaders{virtualKey: "sk-bf-ws"}, wantKind: string(grant.CredentialVirtualKey), wantKey: "sk-bf-ws"},
		"bearer virtual key":  {auth: &authHeaders{authorization: "Bearer sk-bf-bearer"}, wantKind: string(grant.CredentialVirtualKey), wantKey: "sk-bf-bearer"},
		"provider key bearer": {auth: &authHeaders{authorization: "Bearer sk-openai"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := createBifrostContextFromAuth(testWSHandlerStore{}, tc.auth)
			defer cancel()

			g := ctx.Grant()
			if g == nil {
				t.Fatal("expected a grant on the connection context")
			}
			identity := g.Identity()
			if identity == nil {
				t.Fatal("expected a settled identity on the grant")
			}
			if got := identity.Credential(); got.Kind != tc.wantKind || got.Value != tc.wantKey {
				t.Fatalf("credential = %+v, want kind %q value %q", got, tc.wantKind, tc.wantKey)
			}
		})
	}
}

func TestCreateBifrostContextFromAuth_EmptyBaggageSessionIDIgnored(t *testing.T) {
	ctx, cancel := createBifrostContextFromAuth(testWSHandlerStore{}, &authHeaders{
		baggage: "session-id=   ",
	})
	defer cancel()

	if got := ctx.Value(schemas.BifrostContextKeyParentRequestID); got != nil {
		t.Fatalf("parent request id should be unset, got %#v", got)
	}
}

func TestCreateBifrostContextFromAuth_ForwardsPrefixedHeaders(t *testing.T) {
	ctx, cancel := createBifrostContextFromAuth(testWSHandlerStore{}, &authHeaders{
		headers: map[string][]string{
			"x-bf-eh-originator": {"my-test-client"},
			"x-bf-eh-x-trace-id": {"abc-123"},
			"x-bf-eh-cookie":     {"blocked"},
		},
	})
	defer cancel()

	extraHeaders, ok := ctx.Value(schemas.BifrostContextKeyExtraHeaders).(map[string][]string)
	if !ok {
		t.Fatal("expected websocket extra headers in context")
	}
	assert.Equal(t, []string{"my-test-client"}, extraHeaders["originator"])
	assert.Equal(t, []string{"abc-123"}, extraHeaders["x-trace-id"])
	assert.NotContains(t, extraHeaders, "cookie")
}

func TestCreateBifrostContextFromAuth_AppliesHeaderFilterAndDirectAllowlist(t *testing.T) {
	matcher := lib.NewHeaderMatcher(&configstoreTables.GlobalHeaderFilterConfig{
		Allowlist: []string{"originator", "anthropic-*"},
		Denylist:  []string{"anthropic-secret"},
	})
	ctx, cancel := createBifrostContextFromAuth(testWSHandlerStore{matcher: matcher}, &authHeaders{
		headers: map[string][]string{
			"x-bf-eh-originator":       {"allowed-prefix"},
			"x-bf-eh-x-trace-id":       {"blocked-by-allowlist"},
			"anthropic-beta":           {"allowed-direct"},
			"anthropic-secret":         {"blocked-by-denylist"},
			"x-bf-eh-anthropic-secret": {"blocked-prefix-denylist"},
		},
	})
	defer cancel()

	extraHeaders, ok := ctx.Value(schemas.BifrostContextKeyExtraHeaders).(map[string][]string)
	if !ok {
		t.Fatal("expected websocket extra headers in context")
	}
	assert.Equal(t, []string{"allowed-prefix"}, extraHeaders["originator"])
	assert.Equal(t, []string{"allowed-direct"}, extraHeaders["anthropic-beta"])
	assert.NotContains(t, extraHeaders, "x-trace-id")
	assert.NotContains(t, extraHeaders, "anthropic-secret")
}

func TestCaptureAuthHeaders_PreservesDuplicateHeaderValues(t *testing.T) {
	var req fasthttp.Request
	req.Header.Set("Host", "example.test")
	req.Header.Add("x-bf-eh-x-trace-id", "trace-a")
	req.Header.Add("x-bf-eh-x-trace-id", "trace-b")

	ctx := &fasthttp.RequestCtx{}
	ctx.Init(&req, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, nil)

	auth := captureAuthHeaders(ctx)
	assert.Equal(t, []string{"trace-a", "trace-b"}, auth.headers["x-bf-eh-x-trace-id"])
}

func TestCreateBifrostContextFromAuth_PreservesMultipleForwardedHeaderValues(t *testing.T) {
	ctx, cancel := createBifrostContextFromAuth(testWSHandlerStore{}, &authHeaders{
		headers: map[string][]string{
			"x-bf-eh-x-trace-id": {"trace-a", "trace-b"},
		},
	})
	defer cancel()

	extraHeaders, ok := ctx.Value(schemas.BifrostContextKeyExtraHeaders).(map[string][]string)
	if !ok {
		t.Fatal("expected websocket extra headers in context")
	}
	assert.Equal(t, []string{"trace-a", "trace-b"}, extraHeaders["x-trace-id"])
}

func TestCreateBifrostContextFromAuth_BlocksWebSocketHandshakeForwardedHeaders(t *testing.T) {
	matcher := lib.NewHeaderMatcher(&configstoreTables.GlobalHeaderFilterConfig{
		Allowlist: []string{"*"},
	})
	ctx, cancel := createBifrostContextFromAuth(testWSHandlerStore{matcher: matcher}, &authHeaders{
		headers: map[string][]string{
			"x-bf-eh-upgrade":                {"websocket"},
			"x-bf-eh-sec-websocket-protocol": {"realtime"},
			"sec-websocket-extensions":       {"permessage-deflate"},
			"x-bf-eh-originator":             {"safe"},
		},
	})
	defer cancel()

	extraHeaders, ok := ctx.Value(schemas.BifrostContextKeyExtraHeaders).(map[string][]string)
	if !ok {
		t.Fatal("expected websocket extra headers in context")
	}
	assert.Equal(t, []string{"safe"}, extraHeaders["originator"])
	assert.NotContains(t, extraHeaders, "upgrade")
	assert.NotContains(t, extraHeaders, "sec-websocket-protocol")
	assert.NotContains(t, extraHeaders, "sec-websocket-extensions")
}

func TestMergeWebSocketHeaders_ForwardedHeadersOverrideProviderHeadersAndPreserveValues(t *testing.T) {
	ctx := schemas.NewBifrostContext(nil, time.Time{})
	ctx.SetValue(schemas.BifrostContextKeyExtraHeaders, map[string][]string{
		"originator":    {"my-test-client"},
		"authorization": {"Bearer malicious"},
		"x-static":      {"client-value-1", "client-value-2"},
	})

	merged := mergeWebSocketHeaders(ctx, map[string]string{
		"Authorization": "Bearer provider-key",
		"x-static":      "provider-value",
	})

	assert.Equal(t, []string{"my-test-client"}, merged.Values("originator"))
	assert.Equal(t, []string{"Bearer provider-key"}, merged.Values("Authorization"))
	assert.Equal(t, []string{"client-value-1", "client-value-2"}, merged.Values("x-static"))
	assert.NotContains(t, merged.Values("Authorization"), "Bearer malicious")
}

func TestHasWebSocketForwardedHeaders(t *testing.T) {
	ctx := schemas.NewBifrostContext(nil, time.Time{})
	assert.False(t, hasWebSocketForwardedHeaders(ctx))

	ctx.SetValue(schemas.BifrostContextKeyExtraHeaders, map[string][]string{
		"authorization": {"Bearer malicious"},
	})
	assert.False(t, hasWebSocketForwardedHeaders(ctx))

	ctx.SetValue(schemas.BifrostContextKeyExtraHeaders, map[string][]string{
		"x-trace-id": {"abc-123"},
	})
	assert.True(t, hasWebSocketForwardedHeaders(ctx))
}

// Captured handshake credentials must survive each independently created event context.
func TestCreateBifrostContextFromAuth_DirectKeyHeaders(t *testing.T) {
	var handshake fasthttp.RequestCtx
	handshake.Request.Header.Set("Authorization", "Bearer test-oauth-token")
	handshake.Request.Header.Set("x-bf-vk", "sk-bf-test")
	handshake.Request.Header.Set("x-bf-direct-key", "true")
	handshake.Request.Header.Set("x-bf-dim-oauth-email", "test@example.com")
	auth := captureAuthHeaders(&handshake)
	ctx, cancel := createBifrostContextFromAuth(testWSHandlerStore{allowDirectKeys: true}, auth)
	defer cancel()
	assert.Equal(t, "sk-bf-test", ctx.Value(schemas.BifrostContextKeyVirtualKey))
	headers, ok := ctx.Value(schemas.BifrostContextKeyRequestHeaders).(map[string]string)
	if !ok {
		t.Fatal("missing captured request headers")
	}
	assert.Equal(t, "Bearer test-oauth-token", headers["authorization"])
	assert.Equal(t, "true", headers["x-bf-direct-key"])
	assert.Equal(t, "sk-bf-test", headers["x-bf-vk"])
	assert.Equal(t, "test@example.com", headers["x-bf-dim-oauth-email"])
	assert.Equal(t, "test@example.com", ctx.Value(schemas.BifrostContextKeyDimensions).(map[string]string)["oauth-email"])
	key, ok := ctx.Value(schemas.BifrostContextKeyDirectKey).(schemas.Key)
	if !ok {
		t.Fatal("missing direct key")
	}
	assert.Equal(t, "test-oauth-token", key.Value.Val)
	assert.Equal(t, "header-provided", key.ID)
	// A plugin changing one event's headers must not alter later events.
	headers["authorization"] = "changed"
	next, nextCancel := createBifrostContextFromAuth(testWSHandlerStore{allowDirectKeys: true}, auth)
	defer nextCancel()
	assert.Equal(t, "Bearer test-oauth-token", next.Value(schemas.BifrostContextKeyRequestHeaders).(map[string]string)["authorization"])
}

func TestCreateBifrostContextFromAuth_DirectKeyGate(t *testing.T) {
	cases := []struct {
		name                                  string
		allow                                 bool
		flag, bearer, apiKey, googleKey, want string
	}{
		{name: "enabled bearer", allow: true, flag: "true", bearer: "bEaReR test-token", want: "test-token"},
		{name: "server disabled", flag: "true", bearer: "Bearer test-token"},
		{name: "flag absent", allow: true, bearer: "Bearer test-token"},
		{name: "flag false", allow: true, flag: "false", bearer: "Bearer test-token"},
		{name: "virtual key not upstream credential", allow: true, flag: "true", bearer: "Bearer sk-bf-test"},
		{name: "API key fallback", allow: true, flag: "true", apiKey: " test-api ", want: "test-api"},
		{name: "Google key fallback", allow: true, flag: "true", googleKey: "test-google", want: "test-google"},
		{name: "bearer precedence", allow: true, flag: "true", bearer: "Bearer test-token", apiKey: "test-api", want: "test-token"},
		{name: "empty bearer", allow: true, flag: "true", bearer: "Bearer "},
		{name: "non bearer", allow: true, flag: "true", bearer: "Basic test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := &authHeaders{authorization: tc.bearer, apiKey: tc.apiKey, googAPIKey: tc.googleKey, headers: map[string][]string{"x-bf-direct-key": {tc.flag}}}
			ctx, cancel := createBifrostContextFromAuth(testWSHandlerStore{allowDirectKeys: tc.allow}, auth)
			defer cancel()
			key, ok := ctx.Value(schemas.BifrostContextKeyDirectKey).(schemas.Key)
			if tc.want == "" {
				assert.False(t, ok)
				return
			}
			if !ok {
				t.Fatal("missing direct key")
			}
			assert.Equal(t, tc.want, key.Value.Val)
			if ctx.Grant() == nil || ctx.Grant().Identity() == nil {
				t.Fatal("missing settled identity")
			}
			assert.Empty(t, ctx.Grant().Identity().Credential().Value, "direct key selects upstream credentials; it does not identify the gateway caller")
		})
	}
}
