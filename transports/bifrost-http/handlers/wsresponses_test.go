package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fasthttp/websocket"
	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/grant"
	"github.com/maximhq/bifrost/framework/kvstore"
	"github.com/maximhq/bifrost/framework/logstore"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	bfws "github.com/maximhq/bifrost/transports/bifrost-http/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

const routedWSProvider schemas.ModelProvider = "test-codex"

type wsRoutingAccount struct {
	wsSpanTestAccount
	base string
}

func (a wsRoutingAccount) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	return []schemas.ModelProvider{schemas.OpenAI, routedWSProvider}, nil
}
func (a wsRoutingAccount) GetKeysForProvider(ctx context.Context, p schemas.ModelProvider) ([]schemas.Key, error) {
	return a.wsSpanTestAccount.GetKeysForProvider(ctx, schemas.OpenAI)
}
func (a wsRoutingAccount) GetConfigForProvider(p schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	c, _ := a.wsSpanTestAccount.GetConfigForProvider(schemas.OpenAI)
	c.NetworkConfig.BaseURL = a.base
	c.NetworkConfig.AllowPrivateNetwork = true
	c.NetworkConfig.MaxRetries = 0
	if p == routedWSProvider {
		c.CustomProviderConfig = &schemas.CustomProviderConfig{CustomProviderKey: string(p), BaseProviderType: schemas.OpenAI, RequestPathOverrides: map[schemas.RequestType]string{schemas.ResponsesStreamRequest: "/codex/responses"}}
	}
	return c, nil
}

type wsRoutingPlugin struct{ calls atomic.Int32 }

func (p *wsRoutingPlugin) GetName() string { return "test-ws-routing" }
func (p *wsRoutingPlugin) Cleanup() error  { return nil }
func (p *wsRoutingPlugin) PreRequestHook(ctx *schemas.BifrostContext, r *schemas.BifrostRequest) error {
	p.calls.Add(1)
	headers, _ := ctx.Value(schemas.BifrostContextKeyRequestHeaders).(map[string]string)
	if headers["x-bf-direct-key"] != "true" {
		return fmt.Errorf("missing direct-key routing header")
	}
	r.SetProvider(routedWSProvider)
	r.SetModel("routed-model")
	return nil
}
func (p *wsRoutingPlugin) PreLLMHook(_ *schemas.BifrostContext, r *schemas.BifrostRequest) (*schemas.BifrostRequest, *schemas.LLMPluginShortCircuit, error) {
	return r, nil, nil
}
func (p *wsRoutingPlugin) PostLLMHook(_ *schemas.BifrostContext, r *schemas.BifrostResponse, e *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	return r, e, nil
}

func TestWSResponsesRoutesBeforeDialAndPreservesContinuation(t *testing.T) {
	testWSResponsesRouting(t, "native")
}
func TestWSResponsesHTTPBridgeRoutesOnce(t *testing.T) { testWSResponsesRouting(t, "bridge") }
func TestWSResponsesContinuationDoesNotBridge(t *testing.T) {
	testWSResponsesRouting(t, "continuation_failure")
}

func testWSResponsesRouting(t *testing.T, mode string) {
	SetLogger(bifrost.NewDefaultLogger(schemas.LogLevelError))
	var dials, httpCalls atomic.Int32
	events := make(chan map[string]any, 2)
	paths := make(chan string, 4)
	auths := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		auths <- r.Header.Get("Authorization")
		if r.URL.Path != "/codex/responses" {
			http.Error(w, "wrong provider/path", 401)
			return
		}
		if mode != "native" && websocket.IsWebSocketUpgrade(r) {
			http.Error(w, "upgrade unavailable", http.StatusServiceUnavailable)
			return
		}
		if !websocket.IsWebSocketUpgrade(r) {
			httpCalls.Add(1)
			var event map[string]any
			_ = json.NewDecoder(r.Body).Decode(&event)
			events <- event
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_http\",\"model\":\"routed-model\",\"status\":\"completed\",\"output\":[]}}\n\ndata: [DONE]\n\n")
			return
		}
		up := newWSTestUpgrader()
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		dials.Add(1)
		for i := 1; i <= 2; i++ {
			_, raw, err := c.ReadMessage()
			if err != nil {
				return
			}
			var event map[string]any
			_ = json.Unmarshal(raw, &event)
			events <- event
			_ = c.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":"resp_%d","model":"routed-model","status":"completed","output":[]}}`, i)))
		}
		_, _, _ = c.ReadMessage()
	}))
	defer upstream.Close()
	plugin := &wsRoutingPlugin{}
	client, err := bifrost.Init(context.Background(), schemas.BifrostConfig{Account: wsRoutingAccount{base: upstream.URL}, LLMPlugins: []schemas.LLMPlugin{plugin}, Logger: bifrost.NewDefaultLogger(schemas.LogLevelError)})
	require.NoError(t, err)
	defer client.Shutdown()
	pool := bfws.NewPool(nil)
	defer pool.Close()
	h := &WSResponsesHandler{client: client, config: &lib.Config{Providers: map[schemas.ModelProvider]configstore.ProviderConfig{schemas.OpenAI: {}, routedWSProvider: {}}}, handlerStore: testWSHandlerStore{allowDirectKeys: true}, pool: pool}
	done := make(chan struct{})
	results := make(chan []byte, 3)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := newWSTestUpgrader()
		c, e := up.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		defer close(done)
		for {
			_, b, e := c.ReadMessage()
			if e != nil {
				return
			}
			results <- b
		}
	}))
	defer sink.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(sink.URL, "http"), nil)
	require.NoError(t, err)
	session := bfws.NewSession(conn)
	defer session.Close()
	auth := &authHeaders{authorization: "Bearer synthetic-oauth", headers: map[string][]string{"authorization": {"Bearer synthetic-oauth"}, "x-bf-direct-key": {"true"}}}
	turns := 2
	if mode != "native" {
		turns = 1
	}
	for i := 0; i < turns; i++ {
		previous := ""
		if i == 1 || mode == "continuation_failure" {
			previous = `,"previous_response_id":"resp_1"`
		}
		h.handleResponseCreate(session, auth, []byte(`{"type":"response.create","model":"gpt-test","store":false,"input":"hello"`+previous+`}`))
		select {
		case raw := <-results:
			if mode == "continuation_failure" {
				require.Contains(t, string(raw), "previous_response_not_found")
				require.EqualValues(t, 0, httpCalls.Load())
				require.EqualValues(t, 1, plugin.calls.Load())
				return
			}
			require.Contains(t, string(raw), "response.completed")
		case <-time.After(5 * time.Second):
			t.Fatal("no response")
		}
		select {
		case e := <-events:
			require.Equal(t, "routed-model", e["model"])
			require.Equal(t, false, e["store"])
			if i == 1 {
				require.Equal(t, "resp_1", e["previous_response_id"])
			}
		case <-time.After(time.Second):
			t.Fatal("not forwarded")
		}
	}
	if mode == "native" {
		require.EqualValues(t, 1, dials.Load())
		require.EqualValues(t, 0, httpCalls.Load())
	} else {
		require.EqualValues(t, 1, httpCalls.Load())
	}
	require.EqualValues(t, turns, plugin.calls.Load())
	require.Equal(t, "/codex/responses", <-paths)
	require.Equal(t, "Bearer synthetic-oauth", <-auths)
	session.Close()
	<-done
}

func TestWSResponsesAcceptsPreviousResponseWithoutInput(t *testing.T) {
	h := &WSResponsesHandler{}
	req, err := h.convertEventToRequest(&schemas.WebSocketResponsesEvent{Model: "gpt-test", PreviousResponseID: "resp_parent"})
	require.NoError(t, err)
	require.Equal(t, "resp_parent", *req.Params.PreviousResponseID)
	_, err = h.convertEventToRequest(&schemas.WebSocketResponsesEvent{Model: "gpt-test"})
	require.Error(t, err)
}
