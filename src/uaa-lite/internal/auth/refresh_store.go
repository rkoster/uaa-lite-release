package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

//go:generate go run go.uber.org/mock/mockgen -destination=mocks/mock_refresh_store.go -package=mocks . RefreshTokenStore

// RefreshTokenStore manages opaque refresh tokens with in-memory storage
type RefreshTokenStore interface {
	// Store saves a refresh token and returns the opaque token string
	Store(data RefreshTokenData) string

	// Retrieve gets token data and removes it from the store (single use)
	Retrieve(token string) (*RefreshTokenData, error)

	// Count returns the number of active tokens (for monitoring)
	Count() int

	// StartCleanup starts background goroutine to remove expired tokens
	StartCleanup(ctx context.Context, interval time.Duration)
}

// RefreshTokenData contains the metadata associated with a refresh token
type RefreshTokenData struct {
	ClientID  string
	UserID    string // Empty for client_credentials (but those don't get refresh tokens)
	Username  string
	Email     string
	Scope     []string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// inMemoryRefreshStore is the default in-memory implementation of RefreshTokenStore
type inMemoryRefreshStore struct {
	mu     sync.RWMutex
	tokens map[string]*RefreshTokenData
}

// NewRefreshTokenStore creates a new in-memory refresh token store
func NewRefreshTokenStore() RefreshTokenStore {
	return &inMemoryRefreshStore{
		tokens: make(map[string]*RefreshTokenData),
	}
}

// Store saves a refresh token and returns the opaque token string
func (s *inMemoryRefreshStore) Store(data RefreshTokenData) string {
	token := generateOpaqueToken()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[token] = &data
	return token
}

// Retrieve gets token data and removes it from the store (single use)
func (s *inMemoryRefreshStore) Retrieve(token string) (*RefreshTokenData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, exists := s.tokens[token]
	if !exists {
		return nil, errors.New("refresh token not found")
	}

	// Remove from store (single use)
	delete(s.tokens, token)

	// Check if expired
	if time.Now().After(data.ExpiresAt) {
		return nil, errors.New("refresh token expired")
	}

	return data, nil
}

// Count returns the number of active tokens (for monitoring)
func (s *inMemoryRefreshStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.tokens)
}

// StartCleanup starts background goroutine to remove expired tokens
func (s *inMemoryRefreshStore) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.cleanupExpired()
			}
		}
	}()
}

// cleanupExpired removes all expired tokens from the store
func (s *inMemoryRefreshStore) cleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for token, data := range s.tokens {
		if now.After(data.ExpiresAt) {
			delete(s.tokens, token)
		}
	}
}

// generateOpaqueToken generates a cryptographically secure random token
func generateOpaqueToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a less secure but functional token
		// This should never happen in practice
		return base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}
