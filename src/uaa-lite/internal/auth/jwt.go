package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/cloudfoundry/uaa-lite/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

//go:generate go run go.uber.org/mock/mockgen -destination=mocks/mock_jwt_manager.go -package=mocks . JWTManager

// JWTManager handles JWT token creation and validation
type JWTManager interface {
	// CreateAccessToken creates an access token with the given claims
	CreateAccessToken(userID, username, clientID string, scopes []string) (string, error)

	// CreateRefreshToken creates a refresh token
	CreateRefreshToken(userID, username, clientID string) (string, error)

	// ValidateToken validates and parses a JWT token
	ValidateToken(tokenString string) (*Claims, error)

	// GetPublicKey returns the public key for a given key ID
	GetPublicKey(keyID string) (*rsa.PublicKey, error)

	// GetPublicKeys returns all public keys in JWK format
	GetPublicKeys() (map[string]interface{}, error)
}

// jwtManager is the default implementation of JWTManager
type jwtManager struct {
	config *config.Config
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(cfg *config.Config) JWTManager {
	return &jwtManager{
		config: cfg,
	}
}

// CreateAccessToken creates an access token with the given claims
func (m *jwtManager) CreateAccessToken(userID, username, clientID string, scopes []string) (string, error) {
	now := time.Now()
	expiry := now.Add(time.Duration(m.config.JWT.AccessTokenValidity) * time.Second)

	claims := &Claims{
		UserID:   userID,
		UserName: username,
		ClientID: clientID,
		Scope:    scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.config.Server.Issuer,
			Subject:   userID,
			Audience:  DeriveAudience(scopes),
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	// Get active signing key
	privateKey, err := m.config.JWT.GetPrivateKey(m.config.JWT.ActiveKeyID)
	if err != nil {
		return "", fmt.Errorf("failed to get active signing key: %w", err)
	}

	// Create token with RS256 algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.config.JWT.ActiveKeyID

	// Sign the token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// CreateRefreshToken creates a refresh token
func (m *jwtManager) CreateRefreshToken(userID, username, clientID string) (string, error) {
	now := time.Now()
	expiry := now.Add(time.Duration(m.config.JWT.RefreshTokenValidity) * time.Second)

	claims := &Claims{
		UserID:   userID,
		UserName: username,
		ClientID: clientID,
		Scope:    []string{}, // Refresh tokens don't have scopes
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.config.Server.Issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	// Get active signing key
	privateKey, err := m.config.JWT.GetPrivateKey(m.config.JWT.ActiveKeyID)
	if err != nil {
		return "", fmt.Errorf("failed to get active signing key: %w", err)
	}

	// Create token with RS256 algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.config.JWT.ActiveKeyID

	// Sign the token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates and parses a JWT token
func (m *jwtManager) ValidateToken(tokenString string) (*Claims, error) {
	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from header
		kidInterface, ok := token.Header["kid"]
		if !ok {
			return nil, errors.New("missing kid in token header")
		}

		kid, ok := kidInterface.(string)
		if !ok {
			return nil, errors.New("invalid kid in token header")
		}

		// Get public key for verification
		privateKey, err := m.config.JWT.GetPrivateKey(kid)
		if err != nil {
			return nil, fmt.Errorf("failed to get signing key: %w", err)
		}

		return &privateKey.PublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Validate issuer
	if claims.Issuer != m.config.Server.Issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", m.config.Server.Issuer, claims.Issuer)
	}

	return claims, nil
}

// GetPublicKey returns the public key for a given key ID
func (m *jwtManager) GetPublicKey(keyID string) (*rsa.PublicKey, error) {
	privateKey, err := m.config.JWT.GetPrivateKey(keyID)
	if err != nil {
		return nil, err
	}
	return &privateKey.PublicKey, nil
}

// GetPublicKeys returns all public keys in JWK format
func (m *jwtManager) GetPublicKeys() (map[string]interface{}, error) {
	keys := make([]map[string]interface{}, 0, len(m.config.JWT.Keys))

	for keyID := range m.config.JWT.Keys {
		publicKey, err := m.GetPublicKey(keyID)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key for %s: %w", keyID, err)
		}

		// Convert to JWK format
		jwk := map[string]interface{}{
			"kty": "RSA",
			"kid": keyID,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		}

		keys = append(keys, jwk)
	}

	return map[string]interface{}{
		"keys": keys,
	}, nil
}
