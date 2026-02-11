package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/cloudfoundry/uaa-lite/internal/auth"
)

// TokenInfoHandler handles token validation requests at the /oauth/check_token endpoint
type TokenInfoHandler struct {
	jwtManager auth.JWTManager
}

// NewTokenInfoHandler creates a new token info endpoint handler
func NewTokenInfoHandler(jwtManager auth.JWTManager) *TokenInfoHandler {
	return &TokenInfoHandler{
		jwtManager: jwtManager,
	}
}

// TokenInfo represents the response for a validated token
type TokenInfo struct {
	UserID   string   `json:"user_id,omitempty"`
	UserName string   `json:"user_name,omitempty"`
	Email    string   `json:"email,omitempty"`
	ClientID string   `json:"client_id"`
	Scope    []string `json:"scope"`
	Exp      int64    `json:"exp"`
	Iss      string   `json:"iss"`
	Aud      []string `json:"aud"`
}

// ServeHTTP handles the HTTP request for the token info endpoint
func (h *TokenInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	// Extract token from form data
	token := r.Form.Get("token")
	if token == "" {
		h.writeError(w, http.StatusBadRequest, auth.ErrorInvalidRequest, "token is required")
		return
	}

	// Validate token using JWTManager
	claims, err := h.jwtManager.ValidateToken(token)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, auth.ErrorInvalidRequest, "invalid or expired token")
		return
	}

	// Build and write response
	tokenInfo := &TokenInfo{
		UserID:   claims.UserID,
		UserName: claims.UserName,
		Email:    claims.Email,
		ClientID: claims.ClientID,
		Scope:    claims.Scope,
		Exp:      claims.ExpiresAt.Unix(),
		Iss:      claims.Issuer,
		Aud:      claims.Audience,
	}

	h.writeJSON(w, http.StatusOK, tokenInfo)
}

// writeJSON writes a JSON response
func (h *TokenInfoHandler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Log error but don't try to write another response
		// since headers have already been sent
		return
	}
}

// writeError writes an OAuth2 error response
func (h *TokenInfoHandler) writeError(w http.ResponseWriter, statusCode int, errorCode, description string) {
	oauth2Err := auth.NewOAuth2Error(errorCode, description)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(oauth2Err)
}
