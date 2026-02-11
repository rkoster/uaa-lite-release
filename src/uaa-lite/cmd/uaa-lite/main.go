package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cloudfoundry/uaa-lite/internal/auth"
	"github.com/cloudfoundry/uaa-lite/internal/config"
	"github.com/cloudfoundry/uaa-lite/internal/handlers"
	"github.com/gorilla/mux"
)

func main() {
	// Read configuration file path from command line or environment
	configPath := getConfigPath()

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("UAA-Lite starting on https://localhost:%d", cfg.Server.Port)

	// Initialize JWT manager
	jwtManager := auth.NewJWTManager(cfg)

	// Parse TLS certificate and key
	cert, err := tls.X509KeyPair([]byte(cfg.TLS.Certificate), []byte(cfg.TLS.PrivateKey))
	if err != nil {
		log.Fatalf("Failed to parse TLS certificate and key: %v", err)
	}

	// Create router
	router := createRouter(cfg, jwtManager)

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Create HTTP server
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:           router,
		TLSConfig:         tlsConfig,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Handle graceful shutdown
	go func() {
		// Wait for interrupt signal
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigChan

		log.Printf("Received signal: %v, shutting down gracefully...", sig)

		// Create context with timeout for graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Error during graceful shutdown: %v", err)
			os.Exit(1)
		}
	}()

	// Start server with TLS
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	log.Println("Server stopped gracefully")
}

// createRouter creates and configures the HTTP router with all endpoints
func createRouter(cfg *config.Config, jwtManager auth.JWTManager) *mux.Router {
	router := mux.NewRouter()

	// Health check endpoint
	healthHandler := handlers.NewHealthHandler()
	router.Handle("/healthz", healthHandler).Methods(http.MethodGet)

	// Info endpoint
	infoHandler := handlers.NewInfoHandler(cfg.Server.Issuer)
	router.Handle("/info", infoHandler).Methods(http.MethodGet)

	// Token endpoint
	tokenHandler := handlers.NewTokenHandler(cfg, jwtManager)
	router.Handle("/oauth/token", tokenHandler).Methods(http.MethodPost)

	// Token info endpoint (check_token)
	tokenInfoHandler := handlers.NewTokenInfoHandler(jwtManager)
	router.Handle("/oauth/check_token", tokenInfoHandler).Methods(http.MethodPost)

	// JWKS endpoint (all keys)
	jwksHandler := handlers.NewJWKSHandler(jwtManager)
	router.Handle("/token_keys", jwksHandler).Methods(http.MethodGet)

	// Token key endpoint (active key)
	tokenKeyHandler := handlers.NewTokenKeyHandler(jwtManager, cfg)
	router.Handle("/token_key", tokenKeyHandler).Methods(http.MethodGet)

	// Set 405 Method Not Allowed response for other methods on registered routes
	router.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})

	return router
}

// getConfigPath returns the configuration file path from environment or command line
func getConfigPath() string {
	// Check if path provided as command line argument
	if len(os.Args) > 1 {
		return os.Args[1]
	}

	// Check environment variable
	if path := os.Getenv("UAA_CONFIG_PATH"); path != "" {
		return path
	}

	// Default path
	return "/etc/uaa-lite/config.yml"
}
