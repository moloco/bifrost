package openai

import (
	"context"
	"strings"

	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
)

// SupportsWebSocketMode returns true since OpenAI natively supports the Responses API WebSocket Mode.
func (provider *OpenAIProvider) SupportsWebSocketMode() bool {
	return true
}

// WebSocketResponsesURL returns the WebSocket URL for the OpenAI Responses API.
// Converts the HTTP base URL to a WSS URL: https://api.openai.com -> wss://api.openai.com/v1/responses
func (provider *OpenAIProvider) WebSocketResponsesURL(key schemas.Key) string {
	// Prefer a WebSocket-specific endpoint; existing OpenAI-compatible providers
	// commonly configure only the Responses streaming endpoint.
	requestType := schemas.ResponsesStreamRequest
	if cfg := provider.customProviderConfig; cfg != nil && strings.TrimSpace(cfg.RequestPathOverrides[schemas.WebSocketResponsesRequest]) != "" {
		requestType = schemas.WebSocketResponsesRequest
	}
	path, absolute := providerUtils.GetRequestPath(context.Background(), "/v1/responses", provider.customProviderConfig, requestType)
	base := path
	if !absolute {
		base = strings.TrimRight(provider.networkConfig.BaseURL, "/") + path
	}
	base = strings.Replace(base, "https://", "wss://", 1)
	base = strings.Replace(base, "http://", "ws://", 1)
	return base
}

// WebSocketHeaders returns the headers required for the upstream WebSocket connection to OpenAI.
func (provider *OpenAIProvider) WebSocketHeaders(key schemas.Key) map[string]string {
	headers := map[string]string{
		"Authorization": "Bearer " + key.Value.GetValue(),
	}
	for k, v := range provider.networkConfig.ExtraHeaders {
		if strings.EqualFold(k, "Authorization") {
			continue
		}
		headers[k] = v
	}
	return headers
}
