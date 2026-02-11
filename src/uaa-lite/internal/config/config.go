package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
	"os"
)

// Config represents the complete UAA-Lite configuration
type Config struct {
	Server  ServerConfig            `yaml:"server"`
	TLS     TLSConfig               `yaml:"tls"`
	JWT     JWTConfig               `yaml:"jwt"`
	Clients map[string]ClientConfig `yaml:"clients"`
	Users   map[string]UserConfig   `yaml:"users"`
}

// ServerConfig contains server-level configuration
type ServerConfig struct {
	Port   int    `yaml:"port"`
	Issuer string `yaml:"issuer"`
}

// TLSConfig contains TLS certificate configuration
type TLSConfig struct {
	Certificate string `yaml:"certificate"`
	PrivateKey  string `yaml:"private_key"`
}

// JWTConfig contains JWT signing configuration
type JWTConfig struct {
	ActiveKeyID          string                `yaml:"active_key_id"`
	Keys                 map[string]SigningKey `yaml:"keys"`
	AccessTokenValidity  int                   `yaml:"access_token_validity"`
	RefreshTokenValidity int                   `yaml:"refresh_token_validity"`
}

// SigningKey contains an RSA private key for JWT signing
type SigningKey struct {
	SigningKey string          `yaml:"signing_key"` // PEM-encoded RSA private key
	privateKey *rsa.PrivateKey `yaml:"-"`           // Parsed key (not serialized)
}

// ClientConfig contains OAuth client configuration
type ClientConfig struct {
	Secret               string   `yaml:"secret"`
	AuthorizedGrantTypes []string `yaml:"authorized_grant_types"`
	Scope                []string `yaml:"scope"`
	Authorities          []string `yaml:"authorities"`
	AccessTokenValidity  int      `yaml:"access_token_validity"`
	RefreshTokenValidity int      `yaml:"refresh_token_validity"`
}

// UserConfig contains user configuration
type UserConfig struct {
	Password     string   `yaml:"password"` // Plaintext, will be hashed
	PasswordHash string   `yaml:"-"`        // Bcrypt hash, populated on load
	Email        string   `yaml:"email"`
	Groups       []string `yaml:"groups"`
	ID           string   `yaml:"-"` // Generated UUID v5 from username
}

// ConfigLoader is the interface for loading configuration
//
//go:generate go run go.uber.org/mock/mockgen -destination=mocks/mock_config_loader.go -package=mocks . ConfigLoader
type ConfigLoader interface {
	Load(path string) (*Config, error)
}

// defaultLoader is the default implementation of ConfigLoader
type defaultLoader struct{}

// NewLoader creates a new ConfigLoader
func NewLoader() ConfigLoader {
	return &defaultLoader{}
}

// Load reads and validates configuration from a YAML file
func (l *defaultLoader) Load(path string) (*Config, error) {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Apply defaults
	applyDefaults(&cfg)

	// Validate and process configuration
	if err := validateAndProcess(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Load is a convenience function that uses the default loader
func Load(path string) (*Config, error) {
	loader := NewLoader()
	return loader.Load(path)
}

// applyDefaults sets default values for optional fields
func applyDefaults(cfg *Config) {
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8443
	}
	if cfg.JWT.AccessTokenValidity == 0 {
		cfg.JWT.AccessTokenValidity = 43200 // 12 hours
	}
	if cfg.JWT.RefreshTokenValidity == 0 {
		cfg.JWT.RefreshTokenValidity = 2592000 // 30 days
	}
}

// validateAndProcess validates the configuration and processes fields
func validateAndProcess(cfg *Config) error {
	// Validate server
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return errors.New("invalid server port")
	}
	if cfg.Server.Issuer == "" {
		return errors.New("server issuer is required")
	}

	// Validate and parse TLS
	if err := validateTLS(&cfg.TLS); err != nil {
		return fmt.Errorf("TLS validation failed: %w", err)
	}

	// Validate and parse JWT keys
	if err := validateJWT(&cfg.JWT); err != nil {
		return fmt.Errorf("JWT validation failed: %w", err)
	}

	// Validate clients
	if err := validateClients(cfg.Clients); err != nil {
		return fmt.Errorf("client validation failed: %w", err)
	}

	// Validate and process users
	if err := processUsers(cfg.Users); err != nil {
		return fmt.Errorf("user processing failed: %w", err)
	}

	return nil
}

// validateTLS validates TLS certificate and key
func validateTLS(tls *TLSConfig) error {
	if tls.Certificate == "" {
		return errors.New("TLS certificate is required")
	}
	if tls.PrivateKey == "" {
		return errors.New("TLS private key is required")
	}

	// Validate certificate and key are valid PEM and match
	certBlock, _ := pem.Decode([]byte(tls.Certificate))
	if certBlock == nil {
		return errors.New("failed to parse TLS certificate PEM")
	}

	keyBlock, _ := pem.Decode([]byte(tls.PrivateKey))
	if keyBlock == nil {
		return errors.New("failed to parse TLS private key PEM")
	}

	return nil
}

// validateJWT validates JWT configuration and parses keys
func validateJWT(jwt *JWTConfig) error {
	if len(jwt.Keys) == 0 {
		return errors.New("at least one JWT signing key is required")
	}

	if jwt.ActiveKeyID == "" {
		return errors.New("active_key_id is required")
	}

	activeKey, exists := jwt.Keys[jwt.ActiveKeyID]
	if !exists {
		return fmt.Errorf("active_key_id '%s' not found in keys", jwt.ActiveKeyID)
	}

	// Parse all signing keys
	for keyID, key := range jwt.Keys {
		privateKey, err := parseRSAPrivateKey(key.SigningKey)
		if err != nil {
			return fmt.Errorf("failed to parse signing key '%s': %w", keyID, err)
		}

		// Validate minimum key size (2048 bits)
		if privateKey.N.BitLen() < 2048 {
			return fmt.Errorf("signing key '%s' must be at least 2048 bits", keyID)
		}

		// Store parsed key
		key.privateKey = privateKey
		jwt.Keys[keyID] = key
	}

	// Ensure active key is valid
	_ = activeKey

	return nil
}

// parseRSAPrivateKey parses a PEM-encoded RSA private key
func parseRSAPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	// Try PKCS1 format first
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	// Try PKCS8 format
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	return rsaKey, nil
}

// GetPrivateKey returns the parsed RSA private key for a given key ID
func (j *JWTConfig) GetPrivateKey(keyID string) (*rsa.PrivateKey, error) {
	key, exists := j.Keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key '%s' not found", keyID)
	}
	if key.privateKey == nil {
		return nil, fmt.Errorf("key '%s' not parsed", keyID)
	}
	return key.privateKey, nil
}

// validateClients validates client configurations
func validateClients(clients map[string]ClientConfig) error {
	for clientID, client := range clients {
		if client.Secret == "" {
			return fmt.Errorf("client '%s' must have a secret", clientID)
		}
		if len(client.AuthorizedGrantTypes) == 0 {
			return fmt.Errorf("client '%s' must have at least one authorized grant type", clientID)
		}

		// Clients with password grant must have scope defined
		for _, grantType := range client.AuthorizedGrantTypes {
			if grantType == "password" && len(client.Scope) == 0 {
				return fmt.Errorf("client '%s' with password grant must have scope defined", clientID)
			}
		}
	}
	return nil
}

// processUsers validates and processes user configurations
func processUsers(users map[string]UserConfig) error {
	for username, user := range users {
		if user.Password == "" {
			return fmt.Errorf("user '%s' must have a password", username)
		}
		if user.Email == "" {
			return fmt.Errorf("user '%s' must have an email", username)
		}

		// Hash password
		hash, err := hashPassword(user.Password)
		if err != nil {
			return fmt.Errorf("failed to hash password for user '%s': %w", username, err)
		}
		user.PasswordHash = hash

		// Generate deterministic user ID
		user.ID = generateUserID(username)

		// Update the map with processed user
		users[username] = user
	}
	return nil
}

// hashPassword hashes a password using bcrypt
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// generateUserID generates a deterministic UUID v5 from a username
func generateUserID(username string) string {
	// UAA-Lite namespace UUID (custom namespace for this project)
	namespace := uuid.MustParse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
	return uuid.NewSHA1(namespace, []byte(username)).String()
}
