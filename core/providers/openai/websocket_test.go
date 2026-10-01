package openai

import (
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestWebSocketResponsesURLOverrides(t *testing.T) {
	for _, tt := range []struct {
		name, base, want string
		overrides        map[schemas.RequestType]string
	}{
		{"default", "https://api.openai.com", "wss://api.openai.com/v1/responses", nil},
		{"stream override", "https://example.test", "wss://example.test/backend-api/codex/responses", map[schemas.RequestType]string{schemas.ResponsesStreamRequest: "/backend-api/codex/responses"}},
		{"websocket precedence", "http://example.test", "ws://example.test/socket", map[schemas.RequestType]string{schemas.WebSocketResponsesRequest: "/socket", schemas.ResponsesStreamRequest: "/stream"}},
		{"absolute override", "https://example.test", "wss://other.test/socket", map[schemas.RequestType]string{schemas.WebSocketResponsesRequest: "https://other.test/socket"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &OpenAIProvider{networkConfig: schemas.NetworkConfig{BaseURL: tt.base}, customProviderConfig: &schemas.CustomProviderConfig{RequestPathOverrides: tt.overrides}}
			require.Equal(t, tt.want, p.WebSocketResponsesURL(schemas.Key{}))
		})
	}
}
