package auth_test

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/cloudfoundry/uaa-lite/internal/auth"
	"github.com/cloudfoundry/uaa-lite/internal/auth/mocks"
	"github.com/cloudfoundry/uaa-lite/internal/config"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("PasswordGrantHandler", func() {
	var (
		handler        auth.GrantHandler
		cfg            *config.Config
		mockJWTManager *mocks.MockJWTManager
		ctrl           *gomock.Controller
	)

	BeforeEach(func() {
		// Create a temporary config file
		tmpDir := GinkgoT().TempDir()
		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte(grantTestConfigYAML), 0644)
		Expect(err).NotTo(HaveOccurred())

		// Load configuration
		cfg, err = config.Load(configPath)
		Expect(err).NotTo(HaveOccurred())

		// Create mock JWT manager
		ctrl = gomock.NewController(GinkgoT())
		mockJWTManager = mocks.NewMockJWTManager(ctrl)

		// Create handler
		handler = auth.NewPasswordGrantHandler(cfg, mockJWTManager)
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("Handle", func() {
		Context("when request is valid", func() {
			It("should return a token response with access and refresh tokens", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					Username:     "admin",
					Password:     "admin-password",
					Scope:        []string{"bosh.admin"},
				}

				// Mock JWT manager calls
				mockJWTManager.EXPECT().
					CreateAccessToken(gomock.Any(), "admin", "bosh_cli", []string{"bosh.admin"}).
					Return("access-token-123", nil)

				mockJWTManager.EXPECT().
					CreateRefreshToken(gomock.Any(), "admin", "bosh_cli").
					Return("refresh-token-456", nil)

				resp, err := handler.Handle(req)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.AccessToken).To(Equal("access-token-123"))
				Expect(resp.RefreshToken).To(Equal("refresh-token-456"))
				Expect(resp.TokenType).To(Equal("bearer"))
				Expect(resp.ExpiresIn).To(Equal(43200))
				Expect(resp.Scope).To(ConsistOf("bosh.admin"))
			})

			It("should use client-specific token validity when configured", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "config_server",
					ClientSecret: "config-secret",
					Username:     "admin",
					Password:     "admin-password",
					Scope:        []string{"config.admin"},
				}

				mockJWTManager.EXPECT().
					CreateAccessToken(gomock.Any(), "admin", "config_server", []string{"config.admin"}).
					Return("access-token-123", nil)

				mockJWTManager.EXPECT().
					CreateRefreshToken(gomock.Any(), "admin", "config_server").
					Return("refresh-token-456", nil)

				resp, err := handler.Handle(req)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.ExpiresIn).To(Equal(7200)) // Client-specific validity
			})

			It("should intersect user groups, client scopes, and requested scopes", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					Username:     "admin",
					Password:     "admin-password",
					Scope:        []string{"bosh.admin", "bosh.read", "invalid.scope"},
				}

				mockJWTManager.EXPECT().
					CreateAccessToken(gomock.Any(), "admin", "bosh_cli", []string{"bosh.admin", "bosh.read"}).
					Return("access-token-123", nil)

				mockJWTManager.EXPECT().
					CreateRefreshToken(gomock.Any(), "admin", "bosh_cli").
					Return("refresh-token-456", nil)

				resp, err := handler.Handle(req)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Scope).To(ConsistOf("bosh.admin", "bosh.read"))
			})

			It("should use all available scopes when no scopes requested", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					Username:     "admin",
					Password:     "admin-password",
					Scope:        []string{},
				}

				mockJWTManager.EXPECT().
					CreateAccessToken(gomock.Any(), "admin", "bosh_cli", []string{"bosh.admin", "bosh.read"}).
					Return("access-token-123", nil)

				mockJWTManager.EXPECT().
					CreateRefreshToken(gomock.Any(), "admin", "bosh_cli").
					Return("refresh-token-456", nil)

				resp, err := handler.Handle(req)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Scope).To(ConsistOf("bosh.admin", "bosh.read"))
			})
		})

		Context("when client_id is missing", func() {
			It("should return invalid_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "",
					ClientSecret: "bosh-secret",
					Username:     "admin",
					Password:     "admin-password",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when client_secret is missing", func() {
			It("should return invalid_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "bosh_cli",
					ClientSecret: "",
					Username:     "admin",
					Password:     "admin-password",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when username is missing", func() {
			It("should return invalid_request error", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					Username:     "",
					Password:     "admin-password",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidRequest))
			})
		})

		Context("when password is missing", func() {
			It("should return invalid_request error", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					Username:     "admin",
					Password:     "",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidRequest))
			})
		})

		Context("when client does not exist", func() {
			It("should return invalid_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "invalid_client",
					ClientSecret: "secret",
					Username:     "admin",
					Password:     "admin-password",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when client secret is incorrect", func() {
			It("should return invalid_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "bosh_cli",
					ClientSecret: "wrong-secret",
					Username:     "admin",
					Password:     "admin-password",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when client is not authorized for password grant", func() {
			It("should return unauthorized_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "refresh_only",
					ClientSecret: "refresh-secret",
					Username:     "admin",
					Password:     "admin-password",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorUnauthorizedClient))
			})
		})

		Context("when user does not exist", func() {
			It("should return invalid_grant error", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					Username:     "nonexistent",
					Password:     "password",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidGrant))
			})
		})

		Context("when password is incorrect", func() {
			It("should return invalid_grant error", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					Username:     "admin",
					Password:     "wrong-password",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidGrant))
			})
		})

		Context("when no valid scopes are available", func() {
			It("should return invalid_scope error", func() {
				req := &auth.TokenRequest{
					GrantType:    "password",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					Username:     "admin",
					Password:     "admin-password",
					Scope:        []string{"invalid.scope", "another.invalid"},
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidScope))
			})
		})
	})
})

var _ = Describe("RefreshTokenGrantHandler", func() {
	var (
		handler        auth.GrantHandler
		cfg            *config.Config
		mockJWTManager *mocks.MockJWTManager
		ctrl           *gomock.Controller
	)

	BeforeEach(func() {
		// Create a temporary config file
		tmpDir := GinkgoT().TempDir()
		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte(grantTestConfigYAML), 0644)
		Expect(err).NotTo(HaveOccurred())

		// Load configuration
		cfg, err = config.Load(configPath)
		Expect(err).NotTo(HaveOccurred())

		// Create mock JWT manager
		ctrl = gomock.NewController(GinkgoT())
		mockJWTManager = mocks.NewMockJWTManager(ctrl)

		// Create handler
		handler = auth.NewRefreshTokenGrantHandler(cfg, mockJWTManager)
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("Handle", func() {
		Context("when request is valid", func() {
			It("should return a token response with new access token", func() {
				// Get the actual user ID from config
				adminUser := cfg.Users["admin"]

				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					RefreshToken: "valid-refresh-token",
					Scope:        []string{"bosh.admin"},
				}

				// Mock ValidateToken to return valid claims
				mockJWTManager.EXPECT().
					ValidateToken("valid-refresh-token").
					Return(&auth.Claims{
						UserID:   adminUser.ID,
						UserName: "admin",
						ClientID: "bosh_cli",
						Scope:    []string{}, // Refresh tokens have no scopes
					}, nil)

				// Mock CreateAccessToken
				mockJWTManager.EXPECT().
					CreateAccessToken(adminUser.ID, "admin", "bosh_cli", []string{"bosh.admin"}).
					Return("new-access-token-789", nil)

				resp, err := handler.Handle(req)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.AccessToken).To(Equal("new-access-token-789"))
				Expect(resp.RefreshToken).To(Equal("valid-refresh-token")) // Reused
				Expect(resp.TokenType).To(Equal("bearer"))
				Expect(resp.ExpiresIn).To(Equal(43200))
				Expect(resp.Scope).To(ConsistOf("bosh.admin"))
			})

			It("should use all available scopes when no scopes requested", func() {
				// Get the actual user ID from config
				adminUser := cfg.Users["admin"]

				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					RefreshToken: "valid-refresh-token",
					Scope:        []string{},
				}

				mockJWTManager.EXPECT().
					ValidateToken("valid-refresh-token").
					Return(&auth.Claims{
						UserID:   adminUser.ID,
						UserName: "admin",
						ClientID: "bosh_cli",
						Scope:    []string{},
					}, nil)

				mockJWTManager.EXPECT().
					CreateAccessToken(adminUser.ID, "admin", "bosh_cli", []string{"bosh.admin", "bosh.read"}).
					Return("new-access-token-789", nil)

				resp, err := handler.Handle(req)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Scope).To(ConsistOf("bosh.admin", "bosh.read"))
			})

			It("should use client-specific token validity when configured", func() {
				// Get the actual user ID from config
				adminUser := cfg.Users["admin"]

				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "config_server",
					ClientSecret: "config-secret",
					RefreshToken: "valid-refresh-token",
					Scope:        []string{"config.admin"},
				}

				mockJWTManager.EXPECT().
					ValidateToken("valid-refresh-token").
					Return(&auth.Claims{
						UserID:   adminUser.ID,
						UserName: "admin",
						ClientID: "config_server",
						Scope:    []string{},
					}, nil)

				mockJWTManager.EXPECT().
					CreateAccessToken(adminUser.ID, "admin", "config_server", []string{"config.admin"}).
					Return("new-access-token-789", nil)

				resp, err := handler.Handle(req)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.ExpiresIn).To(Equal(7200)) // Client-specific validity
			})
		})

		Context("when client_id is missing", func() {
			It("should return invalid_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "",
					ClientSecret: "bosh-secret",
					RefreshToken: "valid-refresh-token",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when client_secret is missing", func() {
			It("should return invalid_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "bosh_cli",
					ClientSecret: "",
					RefreshToken: "valid-refresh-token",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when refresh_token is missing", func() {
			It("should return invalid_request error", func() {
				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					RefreshToken: "",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidRequest))
			})
		})

		Context("when client does not exist", func() {
			It("should return invalid_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "invalid_client",
					ClientSecret: "secret",
					RefreshToken: "valid-refresh-token",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when client secret is incorrect", func() {
			It("should return invalid_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "bosh_cli",
					ClientSecret: "wrong-secret",
					RefreshToken: "valid-refresh-token",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when client is not authorized for refresh_token grant", func() {
			It("should return unauthorized_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "password_only",
					ClientSecret: "password-secret",
					RefreshToken: "valid-refresh-token",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorUnauthorizedClient))
			})
		})

		Context("when refresh token is invalid", func() {
			It("should return invalid_grant error", func() {
				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					RefreshToken: "invalid-token",
				}

				mockJWTManager.EXPECT().
					ValidateToken("invalid-token").
					Return(nil, errors.New("invalid token"))

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidGrant))
			})
		})

		Context("when refresh token client_id does not match", func() {
			It("should return invalid_grant error", func() {
				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					RefreshToken: "valid-refresh-token",
				}

				mockJWTManager.EXPECT().
					ValidateToken("valid-refresh-token").
					Return(&auth.Claims{
						UserID:   "user-id-123",
						UserName: "admin",
						ClientID: "different_client",
						Scope:    []string{},
					}, nil)

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidGrant))
				Expect(oauth2Err.ErrorDescription).To(ContainSubstring("different client"))
			})
		})

		Context("when refresh token has scopes", func() {
			It("should return invalid_grant error", func() {
				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					RefreshToken: "invalid-refresh-token",
				}

				mockJWTManager.EXPECT().
					ValidateToken("invalid-refresh-token").
					Return(&auth.Claims{
						UserID:   "user-id-123",
						UserName: "admin",
						ClientID: "bosh_cli",
						Scope:    []string{"bosh.admin"}, // Invalid for refresh token
					}, nil)

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidGrant))
				Expect(oauth2Err.ErrorDescription).To(ContainSubstring("has scopes"))
			})
		})

		Context("when user no longer exists", func() {
			It("should return invalid_grant error", func() {
				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					RefreshToken: "valid-refresh-token",
				}

				mockJWTManager.EXPECT().
					ValidateToken("valid-refresh-token").
					Return(&auth.Claims{
						UserID:   "nonexistent-user-id",
						UserName: "deleted_user",
						ClientID: "bosh_cli",
						Scope:    []string{},
					}, nil)

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidGrant))
				Expect(oauth2Err.ErrorDescription).To(ContainSubstring("user not found"))
			})
		})

		Context("when no valid scopes are available", func() {
			It("should return invalid_scope error", func() {
				// Get the actual user ID from config
				adminUser := cfg.Users["admin"]

				req := &auth.TokenRequest{
					GrantType:    "refresh_token",
					ClientID:     "bosh_cli",
					ClientSecret: "bosh-secret",
					RefreshToken: "valid-refresh-token",
					Scope:        []string{"invalid.scope"},
				}

				mockJWTManager.EXPECT().
					ValidateToken("valid-refresh-token").
					Return(&auth.Claims{
						UserID:   adminUser.ID,
						UserName: "admin",
						ClientID: "bosh_cli",
						Scope:    []string{},
					}, nil)

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidScope))
			})
		})
	})
})

var _ = Describe("ClientCredentialsGrantHandler", func() {
	var (
		handler        auth.GrantHandler
		cfg            *config.Config
		mockJWTManager *mocks.MockJWTManager
		ctrl           *gomock.Controller
	)

	BeforeEach(func() {
		// Create a temporary config file
		tmpDir := GinkgoT().TempDir()
		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte(grantTestConfigYAML), 0644)
		Expect(err).NotTo(HaveOccurred())

		// Load configuration
		cfg, err = config.Load(configPath)
		Expect(err).NotTo(HaveOccurred())

		// Create mock JWT manager
		ctrl = gomock.NewController(GinkgoT())
		mockJWTManager = mocks.NewMockJWTManager(ctrl)

		// Create handler
		handler = auth.NewClientCredentialsGrantHandler(cfg, mockJWTManager)
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("Handle", func() {
		Context("when request is valid", func() {
			It("should return a token response with access token only (no refresh token)", func() {
				req := &auth.TokenRequest{
					GrantType:    "client_credentials",
					ClientID:     "service_client",
					ClientSecret: "service-secret",
				}

				// Mock JWT manager calls - for client_credentials, client ID is used as user ID
				mockJWTManager.EXPECT().
					CreateAccessToken("service_client", "", "service_client", []string{"uaa.resource", "clients.read", "clients.write"}).
					Return("access-token-123", nil)

				resp, err := handler.Handle(req)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.AccessToken).To(Equal("access-token-123"))
				Expect(resp.RefreshToken).To(BeEmpty()) // No refresh token for client_credentials
				Expect(resp.TokenType).To(Equal("bearer"))
				Expect(resp.ExpiresIn).To(Equal(43200))
				Expect(resp.Scope).To(ConsistOf("uaa.resource", "clients.read", "clients.write"))
			})

			It("should use client-specific token validity when configured", func() {
				req := &auth.TokenRequest{
					GrantType:    "client_credentials",
					ClientID:     "service_client_custom_validity",
					ClientSecret: "service-custom-secret",
				}

				mockJWTManager.EXPECT().
					CreateAccessToken("service_client_custom_validity", "", "service_client_custom_validity", []string{"uaa.resource"}).
					Return("access-token-123", nil)

				resp, err := handler.Handle(req)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.ExpiresIn).To(Equal(3600)) // Client-specific validity
			})

			It("should filter requested scopes against client authorities", func() {
				req := &auth.TokenRequest{
					GrantType:    "client_credentials",
					ClientID:     "service_client",
					ClientSecret: "service-secret",
					Scope:        []string{"uaa.resource", "clients.read", "invalid.scope"},
				}

				mockJWTManager.EXPECT().
					CreateAccessToken("service_client", "", "service_client", []string{"uaa.resource", "clients.read"}).
					Return("access-token-123", nil)

				resp, err := handler.Handle(req)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Scope).To(ConsistOf("uaa.resource", "clients.read"))
			})

			It("should use all authorities when no scopes requested", func() {
				req := &auth.TokenRequest{
					GrantType:    "client_credentials",
					ClientID:     "service_client",
					ClientSecret: "service-secret",
					Scope:        []string{},
				}

				mockJWTManager.EXPECT().
					CreateAccessToken("service_client", "", "service_client", []string{"uaa.resource", "clients.read", "clients.write"}).
					Return("access-token-123", nil)

				resp, err := handler.Handle(req)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Scope).To(ConsistOf("uaa.resource", "clients.read", "clients.write"))
			})
		})

		Context("when client_id is missing", func() {
			It("should return invalid_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "client_credentials",
					ClientID:     "",
					ClientSecret: "service-secret",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when client_secret is missing", func() {
			It("should return invalid_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "client_credentials",
					ClientID:     "service_client",
					ClientSecret: "",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when client does not exist", func() {
			It("should return invalid_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "client_credentials",
					ClientID:     "invalid_client",
					ClientSecret: "secret",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when client secret is incorrect", func() {
			It("should return invalid_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "client_credentials",
					ClientID:     "service_client",
					ClientSecret: "wrong-secret",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when client is not authorized for client_credentials grant", func() {
			It("should return unauthorized_client error", func() {
				req := &auth.TokenRequest{
					GrantType:    "client_credentials",
					ClientID:     "bosh_cli", // Only has password and refresh_token grants
					ClientSecret: "bosh-secret",
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorUnauthorizedClient))
			})
		})

		Context("when no valid scopes are available", func() {
			It("should return invalid_scope error when requested scopes don't match authorities", func() {
				req := &auth.TokenRequest{
					GrantType:    "client_credentials",
					ClientID:     "service_client",
					ClientSecret: "service-secret",
					Scope:        []string{"invalid.scope", "another.invalid"},
				}

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidScope))
			})
		})

		Context("when JWT manager fails", func() {
			It("should return server_error", func() {
				req := &auth.TokenRequest{
					GrantType:    "client_credentials",
					ClientID:     "service_client",
					ClientSecret: "service-secret",
				}

				mockJWTManager.EXPECT().
					CreateAccessToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return("", errors.New("signing failed"))

				resp, err := handler.Handle(req)

				Expect(err).To(HaveOccurred())
				Expect(resp).To(BeNil())
				oauth2Err, ok := err.(*auth.OAuth2Error)
				Expect(ok).To(BeTrue())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorServerError))
			})
		})
	})
})

var _ = Describe("Helper Functions", func() {
	Describe("IsGrantTypeSupported", func() {
		It("should return true for password grant", func() {
			Expect(auth.IsGrantTypeSupported("password")).To(BeTrue())
		})

		It("should return true for refresh_token grant", func() {
			Expect(auth.IsGrantTypeSupported("refresh_token")).To(BeTrue())
		})

		It("should return true for client_credentials grant", func() {
			Expect(auth.IsGrantTypeSupported("client_credentials")).To(BeTrue())
		})

		It("should return false for unsupported grant types", func() {
			Expect(auth.IsGrantTypeSupported("authorization_code")).To(BeFalse())
			Expect(auth.IsGrantTypeSupported("implicit")).To(BeFalse())
			Expect(auth.IsGrantTypeSupported("invalid")).To(BeFalse())
		})
	})

	Describe("NewGrantHandler", func() {
		var cfg *config.Config

		BeforeEach(func() {
			tmpDir := GinkgoT().TempDir()
			configPath := filepath.Join(tmpDir, "config.yml")
			err := os.WriteFile(configPath, []byte(grantTestConfigYAML), 0644)
			Expect(err).NotTo(HaveOccurred())

			cfg, err = config.Load(configPath)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should create PasswordGrantHandler for password grant", func() {
			ctrl := gomock.NewController(GinkgoT())
			defer ctrl.Finish()
			mockJWT := mocks.NewMockJWTManager(ctrl)

			handler, err := auth.NewGrantHandler("password", cfg, mockJWT)

			Expect(err).NotTo(HaveOccurred())
			Expect(handler).NotTo(BeNil())
		})

		It("should create RefreshTokenGrantHandler for refresh_token grant", func() {
			ctrl := gomock.NewController(GinkgoT())
			defer ctrl.Finish()
			mockJWT := mocks.NewMockJWTManager(ctrl)

			handler, err := auth.NewGrantHandler("refresh_token", cfg, mockJWT)

			Expect(err).NotTo(HaveOccurred())
			Expect(handler).NotTo(BeNil())
		})

		It("should create ClientCredentialsGrantHandler for client_credentials grant", func() {
			ctrl := gomock.NewController(GinkgoT())
			defer ctrl.Finish()
			mockJWT := mocks.NewMockJWTManager(ctrl)

			handler, err := auth.NewGrantHandler("client_credentials", cfg, mockJWT)

			Expect(err).NotTo(HaveOccurred())
			Expect(handler).NotTo(BeNil())
		})

		It("should return error for unsupported grant types", func() {
			ctrl := gomock.NewController(GinkgoT())
			defer ctrl.Finish()
			mockJWT := mocks.NewMockJWTManager(ctrl)

			handler, err := auth.NewGrantHandler("authorization_code", cfg, mockJWT)

			Expect(err).To(HaveOccurred())
			Expect(handler).To(BeNil())
			Expect(err.Error()).To(ContainSubstring("unsupported"))
		})
	})
})

// Test configuration for grant handler tests
const grantTestConfigYAML = `
server:
  port: 8443
  issuer: "https://uaa.test.com:8443"

tls:
  certificate: |
    -----BEGIN CERTIFICATE-----
    MIIEbjCCAtagAwIBAgIQHD+fYIdgPF2/SKlH/6R/yzANBgkqhkiG9w0BAQsFADA3
    MQswCQYDVQQGEwJVUzEWMBQGA1UEChMNQ2xvdWQgRm91bmRyeTEQMA4GA1UEAxMH
    VGVzdCBDQTAeFw0yNjAyMTExNTQ4NTRaFw0yNzAyMTExNTQ4NTRaMDgxCzAJBgNV
    BAYTAlVTMRYwFAYDVQQKEw1DbG91ZCBGb3VuZHJ5MREwDwYDVQQDEwh1YWEudGVz
    dDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAMkk9lNddBcuTY+cQHns
    vagSToW/7TTKZf2qixlDajuSF5cN3yiIfHN56s+H/FQraWhpxL7n7n6o1achP37r
    0HOAM/Q0tGo4zJAKMzI3hMAMbXJVX8TNxEvj0x2/0jB6DwPXa5LGGJXmbIO8wNiz
    0/AqEYRnX1LpDLpYlespUCOQnoLmernGOYV7dFxsyL/cw4CX3JwVheDtLCa3wikX
    pddcdSJ3FYY5s44nBAyoETqygsox5eVDXvUX05HluLySMBxgBjDOwL3PdhWGu/j5
    Q57408J1mAAe8D5DNj4io6p9J6MY179gNbmCliNisp51EZFkuUd/gaN4VNsacIVz
    K4qz6PwVW+m0wNCCS9wN9SOEN4gZb/GEd7c84+Ne/S1tjRPVnbiI2JB9BlEqZcgL
    g8nwKeWKlm7hOQ0dOs/9zvLIkn+O4Vm57SIRtIPvspIENWfmzXZP44kx2/gTzC0c
    n9jPI63TdRalxO38K40WFanQwMRb6C9bDCdYGlLTrUZaeQIDAQABo3UwczAOBgNV
    HQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAd
    BgNVHQ4EFgQUN/Mifq9cV1LoHh6kVeI1ndj2+10wHwYDVR0jBBgwFoAU70BwLHq6
    5KQExqmAU3Z1pptlyYgwDQYJKoZIhvcNAQELBQADggGBAMH+LXXBkRmtpV/1mi+V
    8ITCDcgeD0LQeo53fTLVU+5kTj0jlD9+1eQHx4j+gHrzYo0uAlqjBj444vEbbwMv
    NJwfcvZ/nDVwXrVpiAs8Z0rXM1IA2luEUigOyFh8ZrOPIOFEVnQu6lTrT/OFoEtJ
    lvnMsJwLPdRAZmrH/j0YtaWPlchjWjoW2wkAP6xYZrA4OuUMAoLFeorjYmcPSbkI
    KkTOHLu+4uCzx2udITF2wJtVXoq0Zn9QO56rzlV/n4gbZeADTWx4j+3qdlXH0ObX
    qMP/TsJ+b+36OcgXfmsSA4ap1N5UCWMuvpQfFVom41RK4Xbya54M0cgPcwWpZdvu
    rZAC/uModf9EDSiwRb7qbuxWIPlxKWCM21hXvoeA1PRCIkUPE9tEv+KM7qxDRDvl
    lYTEk8aD6E/XtS9nbVHFzVtWgmNXdiuQMG9tOH+O0hNqdDd4yzZE+JVgY3/kgwI8
    +FI3R8pPjALENNa5d0TTg0H0OWuFpHMV1gfb2gB0gS5yJA==
    -----END CERTIFICATE-----
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    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
    -----END RSA PRIVATE KEY-----

jwt:
  active_key_id: "key-1"
  access_token_validity: 43200
  refresh_token_validity: 2592000
  keys:
    key-1:
      signing_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAvnulvHSh5PdsdsvwsjYfbd2bh+Y9DQPRv1dFpovUkpu5Bpw1
        mN6AJyy1ttYTeZ0/AP3NPhoF9KtapgkhLGDB2euBxIAcv4Zap1izeNkdokZFoFHb
        R3ciiQ4qDJb/Md8Hxh+pbTx9ue5YRDX7D8A354J1txigGYS4IvJnbKlnps18VFtl
        Mt7p19dr62WbT13d6ZHv5VFVRGw1+HudCbzTRqTq3YK4fbDooYvHzPCXbBNhh8/u
        Zaqy/wqCK0MDn8+J+iTF1EAGnD1M6mSn7ogwsPrfLxuB93xCelgklZfKnt+rPzVs
        ArwDPQ39tqRK7oZ6CFzM2L76uL2GehRuLj5UoQIDAQABAoIBAAYG8Dc7/YS61iIV
        e+KNAduTv9XB/DvgMLp8LsZWoFLvPcsuwCdmdZRHvuGFI+Kc43R1k2ab+NpFXb3p
        MLUwbpHQTi/YhJBZgPQl7gUsjC/T8g9g565QNQs0eTIiyPpb/elP8SggBN5ljezC
        mdS6wUoVqlcxHp0QF6ogv2hZx999jPjhkcoyN8UbxIwlOo41soF1ZueN+Wx0cr/z
        YFY5+gL4bccaHp9jQHNeE7hod6AAAsQvs4r9V44gSpac1JYnt0iYdytZriGo3doY
        WhvF0SJWCge4Fv06HI6tHgovzdiW5vp5Z/kkFZCRu2PrV4J3PNenCwGFPRAcquEM
        ZlFFK1ECgYEA8FuCJ6n5xjwOgT/+w65BdXbcbJBJcmBc3gAC6oYeWBfvyKcsdeBM
        DnadtBnuhpIu6Gb2PJq6zbt8aiutBNVxgH7J8suig1a1bLicZIrP0+DpVTewZPwg
        6JnBrW/lOApoyn7/yJfHx3dyM6zx4NYHeJZG15FR7FRRrfoNJdjnMy0CgYEAyuEz
        xZvS1MOihjCNepL3CXPU3cmLSK+7VEzQuY8PvYY47hc9UMpYpnzreT20aPBS0+IJ
        liLkDyOO/j/veVb74Qh+CZTVyffWiMtqKsQQUEizoOBRY4RA6uteSc1ys8gEM9RI
        7I7KFxEgAx26txJay8HZttMab3cYjqtTcuyXn8UCgYEAuWGq4lK8PgQGH/Qu19gn
        zqRtYCJtM5VVKziRBzeIYeOcYoNlzEjCAInGGqnBifNn0IHRO28P0yveyriDCu5h
        S3z+34/l+SzAY2mD3hweLUoUTVDVcR3xd9VXRyC9h1qn9j67o4hFYvgike664/HP
        81bcrtj7ea6TDP+GcoF32MUCgYAB+NBlAk+5S7F/tmcZouYNzHdsNHJLIZIjjp+U
        viQ8Blr1TXqGF4FnFN3BDu16+6MCdjb7o5kt4H2aUQrF1ieal1eKRk0RqnwGVlvQ
        0JkL/rjoPmXsHrP21JTVCM8tmisYSd7vla+3K65w+VAASYhiZJ72HPUr0i+F63pj
        KpOKtQKBgQDssIkOvfgjV8+bmZyvviYI9yRwG2OH30b8vffA01xnQUYzBdk9fpJv
        coa1vtqidMVUpfCc+t/7h55GBT2BENaACNzR4QP3dC9VEli+BfTIMj+IoZn5WTy7
        TooV5eUHu7aChLLyuqn99wo4P4uq4af4n+hhV3fDVr5RqMErkswNOA==
        -----END RSA PRIVATE KEY-----

clients:
  bosh_cli:
    secret: "bosh-secret"
    authorized_grant_types:
      - password
      - refresh_token
    scope:
      - bosh.admin
      - bosh.read
    authorities:
      - bosh.admin
  config_server:
    secret: "config-secret"
    authorized_grant_types:
      - password
      - refresh_token
    scope:
      - config.admin
    authorities:
      - config.admin
    access_token_validity: 7200
  refresh_only:
    secret: "refresh-secret"
    authorized_grant_types:
      - refresh_token
    scope:
      - test.scope
    authorities:
      - test.scope
  password_only:
    secret: "password-secret"
    authorized_grant_types:
      - password
    scope:
      - test.scope
    authorities:
      - test.scope
  service_client:
    secret: "service-secret"
    authorized_grant_types:
      - client_credentials
    scope:
      - openid
    authorities:
      - uaa.resource
      - clients.read
      - clients.write
  service_client_custom_validity:
    secret: "service-custom-secret"
    authorized_grant_types:
      - client_credentials
    scope:
      - openid
    authorities:
      - uaa.resource
    access_token_validity: 3600

users:
  admin:
    password: "admin-password"
    email: "admin@test.com"
    groups:
      - bosh.admin
      - bosh.read
      - config.admin
`
