package handlers

import (
	"encoding/json"
	"net/http"
)

// InfoHandler handles the /info endpoint
type InfoHandler struct {
	issuerURL string
}

// InfoResponse represents the response from the /info endpoint
type InfoResponse struct {
	App struct {
		Version string `json:"version"`
	} `json:"app"`
	Links struct {
		UAA   string `json:"uaa"`
		Login string `json:"login"`
	} `json:"links"`
	ZoneName string              `json:"zone_name"`
	EntityID string              `json:"entityID"`
	Prompts  map[string][]string `json:"prompts"`
}

// NewInfoHandler creates a new info endpoint handler
func NewInfoHandler(issuerURL string) *InfoHandler {
	return &InfoHandler{
		issuerURL: issuerURL,
	}
}

// ServeHTTP handles requests for the /info endpoint
func (h *InfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only accept GET requests
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "only GET method is allowed")
		return
	}

	response := InfoResponse{
		ZoneName: "uaa",
		EntityID: h.issuerURL,
	}

	// Set app version
	response.App.Version = "1.0.0"

	// Set links
	response.Links.UAA = h.issuerURL
	response.Links.Login = h.issuerURL

	// Set prompts for login form
	response.Prompts = map[string][]string{
		"username": {"text", "Username"},
		"password": {"password", "Password"},
	}

	h.writeJSON(w, http.StatusOK, response)
}

// writeJSON writes a JSON response
func (h *InfoHandler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		return
	}
}

// writeError writes an error response
func (h *InfoHandler) writeError(w http.ResponseWriter, statusCode int, message string) {
	errorResp := map[string]string{
		"error": message,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResp)
}
