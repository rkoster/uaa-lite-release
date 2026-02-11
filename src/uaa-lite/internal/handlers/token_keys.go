package handlers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"

	"github.com/cloudfoundry/uaa-lite/internal/auth"
)

// TokenKeyHandler handles the /token_key endpoint (returns active key)
type TokenKeyHandler struct {
	jwtManager auth.JWTManager
	config     interface{} // Store config to access ActiveKeyID
}

// TokenKeysHandler handles the /token_keys endpoint (returns all keys)
type TokenKeysHandler struct {
	jwtManager auth.JWTManager
	config     interface{} // Store config to access all keys
}

// PublicKeyJWK represents a single public key in JWK format with PEM encoding
type PublicKeyJWK struct {
	Kty   string `json:"kty"`
	Alg   string `json:"alg"`
	Use   string `json:"use"`
	Kid   string `json:"kid"`
	N     string `json:"n"`
	E     string `json:"e"`
	Value string `json:"value"` // PEM-encoded public key
}

// PublicKeysJWKS represents all public keys in JWKS format
type PublicKeysJWKS struct {
	Keys []PublicKeyJWK `json:"keys"`
}

// NewTokenKeyHandler creates a new token key endpoint handler
func NewTokenKeyHandler(jwtManager auth.JWTManager, config interface{}) *TokenKeyHandler {
	return &TokenKeyHandler{
		jwtManager: jwtManager,
		config:     config,
	}
}

// NewTokenKeysHandler creates a new token keys endpoint handler
func NewTokenKeysHandler(jwtManager auth.JWTManager, config interface{}) *TokenKeysHandler {
	return &TokenKeysHandler{
		jwtManager: jwtManager,
		config:     config,
	}
}

// ServeHTTP handles requests for the /token_key endpoint
func (h *TokenKeyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only accept GET requests
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "only GET method is allowed")
		return
	}

	// Get public keys from JWT manager
	jwks, err := h.jwtManager.GetPublicKeys()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to retrieve public key")
		return
	}

	// Extract keys array from JWKS response - handle both []interface{} (JSON) and []map[string]interface{} (Go code)
	var keysInterface []map[string]interface{}

	switch keysVal := jwks["keys"].(type) {
	case []interface{}:
		// Keys came from JSON unmarshaling
		for _, keyInterface := range keysVal {
			if keyData, ok := keyInterface.(map[string]interface{}); ok {
				keysInterface = append(keysInterface, keyData)
			}
		}
	case []map[string]interface{}:
		// Keys created directly in Go (e.g., in tests)
		keysInterface = keysVal
	default:
		h.writeError(w, http.StatusInternalServerError, "invalid key format")
		return
	}

	if len(keysInterface) == 0 {
		h.writeError(w, http.StatusInternalServerError, "no public keys available")
		return
	}

	// Use the first key (active key) - in practice, we'd look up the active key ID
	keyData := keysInterface[0]

	// Convert to PublicKeyJWK and add PEM encoding
	jwk := h.keyDataToJWK(keyData)

	h.writeJSON(w, http.StatusOK, jwk)
}

// ServeHTTP handles requests for the /token_keys endpoint
func (h *TokenKeysHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only accept GET requests
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "only GET method is allowed")
		return
	}

	// Get public keys from JWT manager
	jwks, err := h.jwtManager.GetPublicKeys()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to retrieve public keys")
		return
	}

	// Extract keys array from JWKS response - handle both []interface{} (JSON) and []map[string]interface{} (Go code)
	var keysInterface []map[string]interface{}

	switch keysVal := jwks["keys"].(type) {
	case []interface{}:
		// Keys came from JSON unmarshaling
		for _, keyInterface := range keysVal {
			if keyData, ok := keyInterface.(map[string]interface{}); ok {
				keysInterface = append(keysInterface, keyData)
			}
		}
	case []map[string]interface{}:
		// Keys created directly in Go (e.g., in tests)
		keysInterface = keysVal
	default:
		h.writeError(w, http.StatusInternalServerError, "invalid keys format")
		return
	}

	// Convert all keys to PublicKeyJWK format with PEM encoding
	keys := make([]PublicKeyJWK, 0, len(keysInterface))
	for _, keyData := range keysInterface {
		jwk := h.keyDataToJWK(keyData)
		keys = append(keys, jwk)
	}

	// Build and write response
	jwksResp := PublicKeysJWKS{
		Keys: keys,
	}

	h.writeJSON(w, http.StatusOK, jwksResp)
}

// keyDataToJWK converts a key data map to PublicKeyJWK with PEM encoding
func (h *TokenKeyHandler) keyDataToJWK(keyData map[string]interface{}) PublicKeyJWK {
	// Extract fields from the key data
	kty, _ := keyData["kty"].(string)
	kid, _ := keyData["kid"].(string)
	use, _ := keyData["use"].(string)
	alg, _ := keyData["alg"].(string)
	nStr, _ := keyData["n"].(string)
	eStr, _ := keyData["e"].(string)

	// Create JWK struct
	jwk := PublicKeyJWK{
		Kty: kty,
		Kid: kid,
		Use: use,
		Alg: alg,
		N:   nStr,
		E:   eStr,
	}

	// Generate PEM encoding from modulus and exponent
	jwk.Value = h.generatePEMFromJWK(nStr, eStr)

	return jwk
}

// keyDataToJWK converts a key data map to PublicKeyJWK with PEM encoding
func (h *TokenKeysHandler) keyDataToJWK(keyData map[string]interface{}) PublicKeyJWK {
	// Extract fields from the key data
	kty, _ := keyData["kty"].(string)
	kid, _ := keyData["kid"].(string)
	use, _ := keyData["use"].(string)
	alg, _ := keyData["alg"].(string)
	nStr, _ := keyData["n"].(string)
	eStr, _ := keyData["e"].(string)

	// Create JWK struct
	jwk := PublicKeyJWK{
		Kty: kty,
		Kid: kid,
		Use: use,
		Alg: alg,
		N:   nStr,
		E:   eStr,
	}

	// Generate PEM encoding from modulus and exponent
	jwk.Value = generatePEMFromJWK(nStr, eStr)

	return jwk
}

// generatePEMFromJWK generates PEM encoding from JWK fields
func (h *TokenKeyHandler) generatePEMFromJWK(nStr, eStr string) string {
	// Decode base64url-encoded modulus and exponent
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return ""
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return ""
	}

	// Convert bytes to big.Int
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	// Create RSA public key
	publicKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	// Marshal to DER format
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}

	// Encode to PEM format
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(pemBlock))
}

// generatePEMFromJWK generates PEM encoding from JWK fields
func generatePEMFromJWK(nStr, eStr string) string {
	// Decode base64url-encoded modulus and exponent
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return ""
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return ""
	}

	// Convert bytes to big.Int
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	// Create RSA public key
	publicKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	// Marshal to DER format
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}

	// Encode to PEM format
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(pemBlock))
}

// writeJSON writes a JSON response
func (h *TokenKeyHandler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		return
	}
}

// writeError writes an error response
func (h *TokenKeyHandler) writeError(w http.ResponseWriter, statusCode int, message string) {
	errorResp := map[string]string{
		"error": message,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResp)
}

// writeJSON writes a JSON response
func (h *TokenKeysHandler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		return
	}
}

// writeError writes an error response
func (h *TokenKeysHandler) writeError(w http.ResponseWriter, statusCode int, message string) {
	errorResp := map[string]string{
		"error": message,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResp)
}
