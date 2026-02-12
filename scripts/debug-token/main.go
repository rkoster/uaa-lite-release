// debug-token: Fetches an OAuth token from UAA and decodes it for debugging.
//
// Usage:
//   go run scripts/debug-token/main.go
//
// Environment variables:
//   UAA_URL           - UAA base URL (default: https://10.246.0.25:8443)
//   CLIENT_ID         - OAuth client ID (default: admin)
//   CLIENT_SECRET     - OAuth client secret (required, or uses BOSH_CLIENT_SECRET)
//   SKIP_TLS_VERIFY   - Skip TLS verification (default: true)

package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func main() {
	uaaURL := getEnv("UAA_URL", "https://10.246.0.25:8443")
	clientID := getEnv("CLIENT_ID", "admin")
	clientSecret := getEnv("CLIENT_SECRET", os.Getenv("BOSH_CLIENT_SECRET"))
	skipTLSVerify := getEnv("SKIP_TLS_VERIFY", "true") == "true"

	if clientSecret == "" {
		fmt.Fprintln(os.Stderr, "Error: CLIENT_SECRET or BOSH_CLIENT_SECRET must be set")
		os.Exit(1)
	}

	fmt.Printf("=== Token Debug Tool ===\n\n")
	fmt.Printf("UAA URL:       %s\n", uaaURL)
	fmt.Printf("Client ID:     %s\n", clientID)
	fmt.Printf("Skip TLS:      %v\n\n", skipTLSVerify)

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLSVerify},
		},
	}

	// Request token using client_credentials grant
	tokenURL := uaaURL + "/oauth/token"
	data := url.Values{
		"grant_type": {"client_credentials"},
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
		os.Exit(1)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(clientID, clientSecret)

	fmt.Printf("=== Request ===\n")
	fmt.Printf("POST %s\n", tokenURL)
	fmt.Printf("Authorization: Basic %s\n", base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret)))
	fmt.Printf("Content-Type: application/x-www-form-urlencoded\n")
	fmt.Printf("Body: %s\n\n", data.Encode())

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error making request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== Response ===\n")
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Headers:\n")
	for k, v := range resp.Header {
		fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
	}
	fmt.Printf("\nBody:\n%s\n\n", prettyJSON(body))

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Token request failed with status %d\n", resp.StatusCode)
		os.Exit(1)
	}

	// Parse token response
	var tokenResp map[string]interface{}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing token response: %v\n", err)
		os.Exit(1)
	}

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok {
		fmt.Fprintln(os.Stderr, "Error: access_token not found in response")
		os.Exit(1)
	}

	fmt.Printf("=== Access Token (raw) ===\n%s\n\n", accessToken)

	// Decode JWT
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		fmt.Fprintf(os.Stderr, "Error: Invalid JWT format (expected 3 parts, got %d)\n", len(parts))
		os.Exit(1)
	}

	fmt.Printf("=== JWT Header ===\n")
	header, err := base64URLDecode(parts[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding header: %v\n", err)
	} else {
		fmt.Printf("%s\n\n", prettyJSON(header))
	}

	fmt.Printf("=== JWT Payload (Claims) ===\n")
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding payload: %v\n", err)
	} else {
		fmt.Printf("%s\n\n", prettyJSON(payload))
	}

	// Parse claims and check for potential issues
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing claims: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== Potential Issues ===\n")
	checkIssues(claims)
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func prettyJSON(data []byte) string {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return string(data)
	}
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(data)
	}
	return string(pretty)
}

func checkIssues(claims map[string]interface{}) {
	issues := []string{}

	// Check scope format
	if scope, ok := claims["scope"]; ok {
		switch scope.(type) {
		case []interface{}:
			issues = append(issues, "SCOPE FORMAT: 'scope' is an array - BOSH Director may expect a space-separated string")
		case string:
			fmt.Println("OK: 'scope' is a string (correct format)")
		}
	} else {
		issues = append(issues, "MISSING: 'scope' claim not found")
	}

	// Check for missing standard UAA claims
	expectedClaims := []string{"jti", "azp", "grant_type", "authorities"}
	for _, c := range expectedClaims {
		if _, ok := claims[c]; !ok {
			issues = append(issues, fmt.Sprintf("MISSING: '%s' claim not found (may be required by BOSH)", c))
		}
	}

	// Check issuer
	if iss, ok := claims["iss"].(string); ok {
		fmt.Printf("OK: Issuer = %s\n", iss)
		if strings.HasSuffix(iss, "/") {
			issues = append(issues, "ISSUER: Has trailing slash - may cause mismatch")
		}
	} else {
		issues = append(issues, "MISSING: 'iss' (issuer) claim not found")
	}

	// Check audience
	if aud, ok := claims["aud"]; ok {
		fmt.Printf("OK: Audience = %v\n", aud)
	} else {
		issues = append(issues, "MISSING: 'aud' (audience) claim not found")
	}

	// Check subject
	if sub, ok := claims["sub"].(string); ok {
		fmt.Printf("OK: Subject = %s\n", sub)
	} else {
		issues = append(issues, "MISSING: 'sub' (subject) claim not found")
	}

	// Check client_id
	if clientID, ok := claims["client_id"].(string); ok {
		fmt.Printf("OK: Client ID = %s\n", clientID)
	} else {
		issues = append(issues, "MISSING: 'client_id' claim not found")
	}

	fmt.Println()
	if len(issues) > 0 {
		fmt.Println("ISSUES FOUND:")
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
	} else {
		fmt.Println("No obvious issues found.")
	}
}
