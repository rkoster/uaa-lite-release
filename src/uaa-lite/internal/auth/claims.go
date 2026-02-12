package auth

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// timeFromUnix converts a Unix timestamp to time.Time
func timeFromUnix(ts int64) time.Time {
	return time.Unix(ts, 0)
}

// Claims represents JWT claims for UAA-Lite tokens
type Claims struct {
	UserID      string   `json:"user_id,omitempty"`
	UserName    string   `json:"user_name,omitempty"`
	Email       string   `json:"email,omitempty"`
	ClientID    string   `json:"client_id"`
	Scope       []string `json:"-"` // Use custom marshaling for scope
	JTI         string   `json:"jti,omitempty"`
	AZP         string   `json:"azp,omitempty"`
	GrantType   string   `json:"grant_type,omitempty"`
	Authorities []string `json:"-"` // Use custom marshaling for authorities
	jwt.RegisteredClaims
}

// claimsJSON is used for custom JSON marshaling of Claims
type claimsJSON struct {
	UserID      string   `json:"user_id,omitempty"`
	UserName    string   `json:"user_name,omitempty"`
	Email       string   `json:"email,omitempty"`
	ClientID    string   `json:"client_id"`
	Scope       []string `json:"scope,omitempty"`
	JTI         string   `json:"jti,omitempty"`
	AZP         string   `json:"azp,omitempty"`
	GrantType   string   `json:"grant_type,omitempty"`
	Authorities []string `json:"authorities,omitempty"`
	Issuer      string   `json:"iss,omitempty"`
	Subject     string   `json:"sub,omitempty"`
	Audience    []string `json:"aud,omitempty"`
	ExpiresAt   int64    `json:"exp,omitempty"`
	IssuedAt    int64    `json:"iat,omitempty"`
}

// MarshalJSON implements custom JSON marshaling to output scope and authorities as arrays
func (c Claims) MarshalJSON() ([]byte, error) {
	j := claimsJSON{
		UserID:    c.UserID,
		UserName:  c.UserName,
		Email:     c.Email,
		ClientID:  c.ClientID,
		Scope:     c.Scope,
		JTI:       c.JTI,
		AZP:       c.AZP,
		GrantType: c.GrantType,
		Issuer:    c.Issuer,
		Subject:   c.Subject,
	}

	// Handle authorities
	if len(c.Authorities) > 0 {
		j.Authorities = c.Authorities
	}

	// Handle audience
	if len(c.Audience) > 0 {
		j.Audience = c.Audience
	}

	// Handle timestamps
	if c.ExpiresAt != nil {
		j.ExpiresAt = c.ExpiresAt.Unix()
	}
	if c.IssuedAt != nil {
		j.IssuedAt = c.IssuedAt.Unix()
	}

	return json.Marshal(j)
}

// UnmarshalJSON implements custom JSON unmarshaling to parse scope and authorities arrays
func (c *Claims) UnmarshalJSON(data []byte) error {
	var j claimsJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}

	c.UserID = j.UserID
	c.UserName = j.UserName
	c.Email = j.Email
	c.ClientID = j.ClientID
	c.JTI = j.JTI
	c.AZP = j.AZP
	c.GrantType = j.GrantType

	// Parse scope from array
	if len(j.Scope) > 0 {
		c.Scope = j.Scope
	}

	// Parse authorities from array
	if len(j.Authorities) > 0 {
		c.Authorities = j.Authorities
	}

	// Set registered claims
	c.Issuer = j.Issuer
	c.Subject = j.Subject
	if len(j.Audience) > 0 {
		c.Audience = j.Audience
	}
	if j.ExpiresAt != 0 {
		c.ExpiresAt = jwt.NewNumericDate(timeFromUnix(j.ExpiresAt))
	}
	if j.IssuedAt != 0 {
		c.IssuedAt = jwt.NewNumericDate(timeFromUnix(j.IssuedAt))
	}

	return nil
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
