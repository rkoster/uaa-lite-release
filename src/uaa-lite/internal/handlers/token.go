package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/cloudfoundry/uaa-lite/internal/auth"
	"github.com/cloudfoundry/uaa-lite/internal/config"
)

// TokenHandler handles OAuth2 token requests at the /oauth/token endpoint
type TokenHandler struct {
	config        *config.Config
	grantHandlers map[string]auth.GrantHandler
}

// NewTokenHandler creates a new token endpoint handler
func NewTokenHandler(cfg *config.Config, jwtManager auth.JWTManager) *TokenHandler {
	// Initialize grant handlers for supported grant types
	grantHandlers := map[string]auth.GrantHandler{
		"password":           auth.NewPasswordGrantHandler(cfg, jwtManager),
		"refresh_token":      auth.NewRefreshTokenGrantHandler(cfg, jwtManager),
		"client_credentials": auth.NewClientCredentialsGrantHandler(cfg, jwtManager),
	}

	return &TokenHandler{
		config:        cfg,
		grantHandlers: grantHandlers,
	}
}

// ServeHTTP handles the HTTP request for the token endpoint
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, auth.ErrorInvalidRequest, "only POST method is allowed")
		return
	}

	// Parse the request body (application/x-www-form-urlencoded)
	if err := r.ParseForm(); err != nil {
		h.writeError(w, http.StatusBadRequest, auth.ErrorInvalidRequest, "failed to parse request body")
		return
	}

	// Extract client credentials from Basic Auth or form parameters
	clientID, clientSecret, err := h.extractClientCredentials(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, auth.ErrorInvalidClient, err.Error())
		return
	}

	// Extract grant type
	grantType := r.Form.Get("grant_type")
	if grantType == "" {
		h.writeError(w, http.StatusBadRequest, auth.ErrorInvalidRequest, "grant_type is required")
		return
	}

	// Build token request
	tokenReq := &auth.TokenRequest{
		GrantType:    grantType,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Username:     r.Form.Get("username"),
		Password:     r.Form.Get("password"),
		RefreshToken: r.Form.Get("refresh_token"),
		Scope:        h.parseScope(r.Form.Get("scope")),
	}

	// Get the appropriate grant handler
	handler, exists := h.grantHandlers[grantType]
	if !exists {
		h.writeError(w, http.StatusBadRequest, auth.ErrorUnsupportedGrantType, "grant type is not supported")
		return
	}

	// Handle the token request
	tokenResp, err := handler.Handle(tokenReq)
	if err != nil {
		// Check if it's an OAuth2Error
		if oauth2Err, ok := err.(*auth.OAuth2Error); ok {
			h.writeOAuth2Error(w, oauth2Err)
		} else {
			h.writeError(w, http.StatusInternalServerError, auth.ErrorServerError, err.Error())
		}
		return
	}

	// Write successful response
	h.writeJSON(w, http.StatusOK, tokenResp)
}

// extractClientCredentials extracts client credentials from Basic Auth or form parameters
func (h *TokenHandler) extractClientCredentials(r *http.Request) (clientID, clientSecret string, err error) {
	// Try Basic Auth first
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, "Basic ") {
			// Decode Basic Auth
			payload := strings.TrimPrefix(authHeader, "Basic ")
			decoded, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return "", "", err
			}

			// Split into client_id and client_secret
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) != 2 {
				return "", "", err
			}

			return parts[0], parts[1], nil
		}
	}

	// Fall back to form parameters
	clientID = r.Form.Get("client_id")
	clientSecret = r.Form.Get("client_secret")

	return clientID, clientSecret, nil
}

// parseScope parses a space-separated scope string into a slice
func (h *TokenHandler) parseScope(scopeStr string) []string {
	if scopeStr == "" {
		return nil
	}

	scopes := strings.Fields(scopeStr)
	return scopes
}

// writeJSON writes a JSON response
func (h *TokenHandler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Log error but don't try to write another response
		// since headers have already been sent
		return
	}
}

// writeError writes an OAuth2 error response
func (h *TokenHandler) writeError(w http.ResponseWriter, statusCode int, errorCode, description string) {
	oauth2Err := auth.NewOAuth2Error(errorCode, description)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(oauth2Err)
}

// writeOAuth2Error writes an OAuth2Error response with HTTP 400
func (h *TokenHandler) writeOAuth2Error(w http.ResponseWriter, err *auth.OAuth2Error) {
	h.writeJSON(w, http.StatusBadRequest, err)
}
