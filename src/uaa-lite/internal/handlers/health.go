package handlers

import (
	"encoding/json"
	"net/http"
)

// HealthHandler handles health check requests at the /healthz endpoint
type HealthHandler struct{}

// NewHealthHandler creates a new health check endpoint handler
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// HealthResponse represents the response for a health check
type HealthResponse struct {
	Status string `json:"status"`
}

// ServeHTTP handles the HTTP request for the health check endpoint
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only accept GET requests
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "only GET method is allowed")
		return
	}

	// Return healthy status
	healthResp := &HealthResponse{
		Status: "ok",
	}

	h.writeJSON(w, http.StatusOK, healthResp)
}

// writeJSON writes a JSON response
func (h *HealthHandler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Log error but don't try to write another response
		// since headers have already been sent
		return
	}
}

// writeError writes an error response
func (h *HealthHandler) writeError(w http.ResponseWriter, statusCode int, message string) {
	errorResp := map[string]string{
		"error": message,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResp)
}
