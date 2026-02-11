package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/cloudfoundry/uaa-lite/internal/auth"
)

// JWKSHandler handles public key discovery requests at the /token_keys endpoint
type JWKSHandler struct {
	jwtManager auth.JWTManager
}

// NewJWKSHandler creates a new JWKS endpoint handler
func NewJWKSHandler(jwtManager auth.JWTManager) *JWKSHandler {
	return &JWKSHandler{
		jwtManager: jwtManager,
	}
}

// ServeHTTP handles the HTTP request for the JWKS endpoint
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only accept GET requests
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "only GET method is allowed")
		return
	}

	// Get public keys in JWKS format
	jwks, err := h.jwtManager.GetPublicKeys()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to retrieve public keys")
		return
	}

	// Write successful response
	h.writeJSON(w, http.StatusOK, jwks)
}

// writeJSON writes a JSON response
func (h *JWKSHandler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Log error but don't try to write another response
		// since headers have already been sent
		return
	}
}

// writeError writes an error response
func (h *JWKSHandler) writeError(w http.ResponseWriter, statusCode int, message string) {
	errorResp := map[string]string{
		"error": message,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResp)
}
