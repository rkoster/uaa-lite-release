package auth

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents JWT claims for UAA-Lite tokens
type Claims struct {
	UserID   string   `json:"user_id,omitempty"`
	UserName string   `json:"user_name,omitempty"`
	Email    string   `json:"email,omitempty"`
	ClientID string   `json:"client_id"`
	Scope    []string `json:"scope"`
	jwt.RegisteredClaims
}

// DeriveAudience extracts unique audience values from scopes
// Audience is derived from scope prefixes (e.g., "bosh.admin" -> "bosh")
func DeriveAudience(scopes []string) []string {
	audienceMap := make(map[string]bool)

	for _, scope := range scopes {
		// Extract prefix before first dot
		parts := strings.SplitN(scope, ".", 2)
		if len(parts) > 0 && parts[0] != "" {
			audienceMap[parts[0]] = true
		}
	}

	// Convert map to slice
	audience := make([]string, 0, len(audienceMap))
	for aud := range audienceMap {
		audience = append(audience, aud)
	}

	return audience
}
