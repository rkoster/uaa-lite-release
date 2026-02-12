package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/cloudfoundry/uaa-lite/internal/config"
	"golang.org/x/crypto/bcrypt"
)

//go:generate go run go.uber.org/mock/mockgen -destination=mocks/mock_grant_handler.go -package=mocks . GrantHandler

// OAuth2 error codes as per RFC 6749
const (
	ErrorInvalidRequest       = "invalid_request"
	ErrorInvalidClient        = "invalid_client"
	ErrorInvalidGrant         = "invalid_grant"
	ErrorUnauthorizedClient   = "unauthorized_client"
	ErrorUnsupportedGrantType = "unsupported_grant_type"
	ErrorInvalidScope         = "invalid_scope"
	ErrorAccessDenied         = "access_denied"
	ErrorServerError          = "server_error"
)

// OAuth2Error represents an OAuth2 error response
type OAuth2Error struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Error implements the error interface
func (e *OAuth2Error) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrorCode, e.ErrorDescription)
}

// NewOAuth2Error creates a new OAuth2Error
func NewOAuth2Error(errorCode, description string) *OAuth2Error {
	return &OAuth2Error{
		ErrorCode:        errorCode,
		ErrorDescription: description,
	}
}

// TokenRequest represents an OAuth2 token request
type TokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
	RefreshToken string
	Scope        []string
}

// TokenResponse represents an OAuth2 token response
type TokenResponse struct {
	AccessToken  string   `json:"access_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	Scope        []string `json:"scope"`
}

// GrantHandler handles OAuth2 grant type requests
type GrantHandler interface {
	Handle(req *TokenRequest) (*TokenResponse, error)
}

// PasswordGrantHandler handles the password grant type
type PasswordGrantHandler struct {
	config     *config.Config
	jwtManager JWTManager
}

// NewPasswordGrantHandler creates a new password grant handler
func NewPasswordGrantHandler(cfg *config.Config, jwtManager JWTManager) GrantHandler {
	return &PasswordGrantHandler{
		config:     cfg,
		jwtManager: jwtManager,
	}
}

// Handle processes a password grant request
func (h *PasswordGrantHandler) Handle(req *TokenRequest) (*TokenResponse, error) {
	// Validate request
	if req.ClientID == "" || req.ClientSecret == "" {
		return nil, NewOAuth2Error(ErrorInvalidClient, "client_id and client_secret are required")
	}
	if req.Username == "" || req.Password == "" {
		return nil, NewOAuth2Error(ErrorInvalidRequest, "username and password are required")
	}

	// Authenticate client
	client, err := h.authenticateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	// Verify client is authorized for password grant
	if !h.isGrantTypeAuthorized(client, "password") {
		return nil, NewOAuth2Error(ErrorUnauthorizedClient, "client is not authorized for password grant")
	}

	// Authenticate user
	user, username, err := h.authenticateUser(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	// Calculate effective scopes (intersection of user groups, client scopes, and requested scopes)
	effectiveScopes := h.calculateScopes(user.Groups, client.Scope, req.Scope)
	if len(effectiveScopes) == 0 {
		return nil, NewOAuth2Error(ErrorInvalidScope, "no valid scopes available")
	}

	// Get token validity (use client-specific or global defaults)
	accessTokenValidity := h.config.JWT.AccessTokenValidity
	if client.AccessTokenValidity > 0 {
		accessTokenValidity = client.AccessTokenValidity
	}

	// Note: refreshTokenValidity is determined by JWT config and client config
	// but is not used here as the token's expiration is set during creation

	// Create access token
	accessToken, err := h.jwtManager.CreateAccessTokenWithOptions(user.ID, username, req.ClientID, effectiveScopes, TokenOptions{
		GrantType: "password",
	})
	if err != nil {
		return nil, NewOAuth2Error(ErrorServerError, fmt.Sprintf("failed to create access token: %v", err))
	}

	// Create refresh token
	refreshToken, err := h.jwtManager.CreateRefreshToken(user.ID, username, req.ClientID)
	if err != nil {
		return nil, NewOAuth2Error(ErrorServerError, fmt.Sprintf("failed to create refresh token: %v", err))
	}

	// Build response
	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		ExpiresIn:    accessTokenValidity,
		RefreshToken: refreshToken,
		Scope:        effectiveScopes,
	}, nil
}

// authenticateClient validates client credentials using constant-time comparison
func (h *PasswordGrantHandler) authenticateClient(clientID, clientSecret string) (*config.ClientConfig, error) {
	client, exists := h.config.Clients[clientID]
	if !exists {
		return nil, NewOAuth2Error(ErrorInvalidClient, "invalid client credentials")
	}

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
		return nil, NewOAuth2Error(ErrorInvalidClient, "invalid client credentials")
	}

	return &client, nil
}

// authenticateUser validates user credentials
func (h *PasswordGrantHandler) authenticateUser(username, password string) (*config.UserConfig, string, error) {
	user, exists := h.config.Users[username]
	if !exists {
		return nil, "", NewOAuth2Error(ErrorInvalidGrant, "invalid username or password")
	}

	// Compare password with bcrypt hash
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, "", NewOAuth2Error(ErrorInvalidGrant, "invalid username or password")
	}

	return &user, username, nil
}

// isGrantTypeAuthorized checks if a client is authorized for a grant type
func (h *PasswordGrantHandler) isGrantTypeAuthorized(client *config.ClientConfig, grantType string) bool {
	for _, authorizedGrant := range client.AuthorizedGrantTypes {
		if authorizedGrant == grantType {
			return true
		}
	}
	return false
}

// calculateScopes computes the intersection of user groups, client scopes, and requested scopes
func (h *PasswordGrantHandler) calculateScopes(userGroups, clientScopes, requestedScopes []string) []string {
	// If no scopes requested, use all available scopes from user groups and client
	if len(requestedScopes) == 0 {
		requestedScopes = append(userGroups, clientScopes...)
	}

	// Build sets for efficient lookup
	userGroupSet := make(map[string]bool)
	for _, group := range userGroups {
		userGroupSet[group] = true
	}

	clientScopeSet := make(map[string]bool)
	for _, scope := range clientScopes {
		clientScopeSet[scope] = true
	}

	// Calculate intersection: scope must be in user groups AND client scopes AND requested scopes
	var effectiveScopes []string
	seen := make(map[string]bool)
	for _, scope := range requestedScopes {
		// Skip duplicates
		if seen[scope] {
			continue
		}
		seen[scope] = true

		// Scope must be in both user groups and client scopes
		if userGroupSet[scope] && clientScopeSet[scope] {
			effectiveScopes = append(effectiveScopes, scope)
		}
	}

	return effectiveScopes
}

// RefreshTokenGrantHandler handles the refresh_token grant type
type RefreshTokenGrantHandler struct {
	config     *config.Config
	jwtManager JWTManager
}

// NewRefreshTokenGrantHandler creates a new refresh token grant handler
func NewRefreshTokenGrantHandler(cfg *config.Config, jwtManager JWTManager) GrantHandler {
	return &RefreshTokenGrantHandler{
		config:     cfg,
		jwtManager: jwtManager,
	}
}

// Handle processes a refresh token grant request
func (h *RefreshTokenGrantHandler) Handle(req *TokenRequest) (*TokenResponse, error) {
	// Validate request
	if req.ClientID == "" || req.ClientSecret == "" {
		return nil, NewOAuth2Error(ErrorInvalidClient, "client_id and client_secret are required")
	}
	if req.RefreshToken == "" {
		return nil, NewOAuth2Error(ErrorInvalidRequest, "refresh_token is required")
	}

	// Authenticate client
	client, err := h.authenticateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	// Verify client is authorized for refresh_token grant
	if !h.isGrantTypeAuthorized(client, "refresh_token") {
		return nil, NewOAuth2Error(ErrorUnauthorizedClient, "client is not authorized for refresh_token grant")
	}

	// Validate refresh token
	claims, err := h.jwtManager.ValidateToken(req.RefreshToken)
	if err != nil {
		return nil, NewOAuth2Error(ErrorInvalidGrant, fmt.Sprintf("invalid refresh token: %v", err))
	}

	// Verify client ID matches
	if claims.ClientID != req.ClientID {
		return nil, NewOAuth2Error(ErrorInvalidGrant, "refresh token was issued to a different client")
	}

	// Verify token has no scopes (refresh tokens should not have scopes)
	if len(claims.Scope) > 0 {
		return nil, NewOAuth2Error(ErrorInvalidGrant, "invalid refresh token: token has scopes")
	}

	// Get user from config to retrieve current groups/scopes
	var userGroups []string
	for _, user := range h.config.Users {
		if user.ID == claims.UserID {
			userGroups = user.Groups
			break
		}
	}

	if userGroups == nil {
		return nil, NewOAuth2Error(ErrorInvalidGrant, "user not found")
	}

	// Calculate effective scopes for new access token
	effectiveScopes := h.calculateScopes(userGroups, client.Scope, req.Scope)
	if len(effectiveScopes) == 0 {
		return nil, NewOAuth2Error(ErrorInvalidScope, "no valid scopes available")
	}

	// Get token validity (use client-specific or global defaults)
	accessTokenValidity := h.config.JWT.AccessTokenValidity
	if client.AccessTokenValidity > 0 {
		accessTokenValidity = client.AccessTokenValidity
	}

	// Create new access token
	accessToken, err := h.jwtManager.CreateAccessTokenWithOptions(claims.UserID, claims.UserName, req.ClientID, effectiveScopes, TokenOptions{
		GrantType: "refresh_token",
	})
	if err != nil {
		return nil, NewOAuth2Error(ErrorServerError, fmt.Sprintf("failed to create access token: %v", err))
	}

	// Build response (reuse existing refresh token)
	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		ExpiresIn:    accessTokenValidity,
		RefreshToken: req.RefreshToken, // Reuse existing refresh token
		Scope:        effectiveScopes,
	}, nil
}

// authenticateClient validates client credentials using constant-time comparison
func (h *RefreshTokenGrantHandler) authenticateClient(clientID, clientSecret string) (*config.ClientConfig, error) {
	client, exists := h.config.Clients[clientID]
	if !exists {
		return nil, NewOAuth2Error(ErrorInvalidClient, "invalid client credentials")
	}

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
		return nil, NewOAuth2Error(ErrorInvalidClient, "invalid client credentials")
	}

	return &client, nil
}

// isGrantTypeAuthorized checks if a client is authorized for a grant type
func (h *RefreshTokenGrantHandler) isGrantTypeAuthorized(client *config.ClientConfig, grantType string) bool {
	for _, authorizedGrant := range client.AuthorizedGrantTypes {
		if authorizedGrant == grantType {
			return true
		}
	}
	return false
}

// calculateScopes computes the intersection of user groups, client scopes, and requested scopes
func (h *RefreshTokenGrantHandler) calculateScopes(userGroups, clientScopes, requestedScopes []string) []string {
	// If no scopes requested, use all available scopes from user groups and client
	if len(requestedScopes) == 0 {
		requestedScopes = append(userGroups, clientScopes...)
	}

	// Build sets for efficient lookup
	userGroupSet := make(map[string]bool)
	for _, group := range userGroups {
		userGroupSet[group] = true
	}

	clientScopeSet := make(map[string]bool)
	for _, scope := range clientScopes {
		clientScopeSet[scope] = true
	}

	// Calculate intersection: scope must be in user groups AND client scopes AND requested scopes
	var effectiveScopes []string
	seen := make(map[string]bool)
	for _, scope := range requestedScopes {
		// Skip duplicates
		if seen[scope] {
			continue
		}
		seen[scope] = true

		// Scope must be in both user groups and client scopes
		if userGroupSet[scope] && clientScopeSet[scope] {
			effectiveScopes = append(effectiveScopes, scope)
		}
	}

	return effectiveScopes
}

// ClientCredentialsGrantHandler handles the client_credentials grant type
type ClientCredentialsGrantHandler struct {
	config     *config.Config
	jwtManager JWTManager
}

// NewClientCredentialsGrantHandler creates a new client credentials grant handler
func NewClientCredentialsGrantHandler(cfg *config.Config, jwtManager JWTManager) GrantHandler {
	return &ClientCredentialsGrantHandler{
		config:     cfg,
		jwtManager: jwtManager,
	}
}

// Handle processes a client credentials grant request
func (h *ClientCredentialsGrantHandler) Handle(req *TokenRequest) (*TokenResponse, error) {
	// Validate request
	if req.ClientID == "" || req.ClientSecret == "" {
		return nil, NewOAuth2Error(ErrorInvalidClient, "client_id and client_secret are required")
	}

	// Authenticate client
	client, err := h.authenticateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	// Verify client is authorized for client_credentials grant
	if !h.isGrantTypeAuthorized(client, "client_credentials") {
		return nil, NewOAuth2Error(ErrorUnauthorizedClient, "client is not authorized for client_credentials grant")
	}

	// For client_credentials grant, scopes come from client authorities
	// If scopes are requested, they must be a subset of client authorities
	effectiveScopes := h.calculateScopes(client.Authorities, req.Scope)
	if len(effectiveScopes) == 0 {
		return nil, NewOAuth2Error(ErrorInvalidScope, "no valid scopes available")
	}

	// Get token validity (use client-specific or global defaults)
	accessTokenValidity := h.config.JWT.AccessTokenValidity
	if client.AccessTokenValidity > 0 {
		accessTokenValidity = client.AccessTokenValidity
	}

	// Create access token (no user context for client_credentials)
	// Use client ID as both userID and username since there's no user
	accessToken, err := h.jwtManager.CreateAccessTokenWithOptions(req.ClientID, "", req.ClientID, effectiveScopes, TokenOptions{
		GrantType:   "client_credentials",
		Authorities: client.Authorities,
	})
	if err != nil {
		return nil, NewOAuth2Error(ErrorServerError, fmt.Sprintf("failed to create access token: %v", err))
	}

	// Build response (no refresh token for client_credentials grant)
	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "bearer",
		ExpiresIn:   accessTokenValidity,
		Scope:       effectiveScopes,
	}, nil
}

// authenticateClient validates client credentials using constant-time comparison
func (h *ClientCredentialsGrantHandler) authenticateClient(clientID, clientSecret string) (*config.ClientConfig, error) {
	client, exists := h.config.Clients[clientID]
	if !exists {
		return nil, NewOAuth2Error(ErrorInvalidClient, "invalid client credentials")
	}

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
		return nil, NewOAuth2Error(ErrorInvalidClient, "invalid client credentials")
	}

	return &client, nil
}

// isGrantTypeAuthorized checks if a client is authorized for a grant type
func (h *ClientCredentialsGrantHandler) isGrantTypeAuthorized(client *config.ClientConfig, grantType string) bool {
	for _, authorizedGrant := range client.AuthorizedGrantTypes {
		if authorizedGrant == grantType {
			return true
		}
	}
	return false
}

// calculateScopes computes effective scopes for client credentials grant
// For client_credentials, scopes come from client authorities
func (h *ClientCredentialsGrantHandler) calculateScopes(authorities, requestedScopes []string) []string {
	// Build set of client authorities
	authoritySet := make(map[string]bool)
	for _, authority := range authorities {
		authoritySet[authority] = true
	}

	// If no scopes requested, use all authorities
	if len(requestedScopes) == 0 {
		return authorities
	}

	// Filter requested scopes to only those in authorities
	var effectiveScopes []string
	seen := make(map[string]bool)
	for _, scope := range requestedScopes {
		// Skip duplicates
		if seen[scope] {
			continue
		}
		seen[scope] = true

		// Scope must be in client authorities
		if authoritySet[scope] {
			effectiveScopes = append(effectiveScopes, scope)
		}
	}

	return effectiveScopes
}

// Helper function to check if a grant type is supported
func IsGrantTypeSupported(grantType string) bool {
	return grantType == "password" || grantType == "refresh_token" || grantType == "client_credentials"
}

// Helper function to create a grant handler for a specific grant type
func NewGrantHandler(grantType string, cfg *config.Config, jwtManager JWTManager) (GrantHandler, error) {
	switch grantType {
	case "password":
		return NewPasswordGrantHandler(cfg, jwtManager), nil
	case "refresh_token":
		return NewRefreshTokenGrantHandler(cfg, jwtManager), nil
	case "client_credentials":
		return NewClientCredentialsGrantHandler(cfg, jwtManager), nil
	default:
		return nil, errors.New("unsupported grant type")
	}
}
