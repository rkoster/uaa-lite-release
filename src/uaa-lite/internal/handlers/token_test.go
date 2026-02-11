package handlers_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudfoundry/uaa-lite/internal/auth"
	"github.com/cloudfoundry/uaa-lite/internal/auth/mocks"
	"github.com/cloudfoundry/uaa-lite/internal/config"
	"github.com/cloudfoundry/uaa-lite/internal/handlers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("TokenHandler", func() {
	var (
		handler        *handlers.TokenHandler
		cfg            *config.Config
		mockJWTManager *mocks.MockJWTManager
		ctrl           *gomock.Controller
		recorder       *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		// Create a temporary config file
		tmpDir := GinkgoT().TempDir()
		configPath := filepath.Join(tmpDir, "config.yml")
		err := os.WriteFile(configPath, []byte(tokenHandlerTestConfigYAML), 0644)
		Expect(err).NotTo(HaveOccurred())

		// Load configuration
		cfg, err = config.Load(configPath)
		Expect(err).NotTo(HaveOccurred())

		// Create mock JWT manager
		ctrl = gomock.NewController(GinkgoT())
		mockJWTManager = mocks.NewMockJWTManager(ctrl)

		// Create handler
		handler = handlers.NewTokenHandler(cfg, mockJWTManager)

		// Create response recorder
		recorder = httptest.NewRecorder()
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("ServeHTTP", func() {
		Context("with password grant type", func() {
			It("should successfully return tokens with form-encoded credentials", func() {
				// Setup mock expectations
				mockJWTManager.EXPECT().
					CreateAccessToken(gomock.Any(), "admin", "bosh_cli", []string{"bosh.admin"}).
					Return("access-token-123", nil)

				mockJWTManager.EXPECT().
					CreateRefreshToken(gomock.Any(), "admin", "bosh_cli").
					Return("refresh-token-456", nil)

				// Create request
				form := url.Values{}
				form.Set("grant_type", "password")
				form.Set("client_id", "bosh_cli")
				form.Set("client_secret", "bosh-secret")
				form.Set("username", "admin")
				form.Set("password", "admin-password")
				form.Set("scope", "bosh.admin")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))
				Expect(recorder.Header().Get("Content-Type")).To(Equal("application/json"))

				var tokenResp auth.TokenResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &tokenResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokenResp.AccessToken).To(Equal("access-token-123"))
				Expect(tokenResp.RefreshToken).To(Equal("refresh-token-456"))
				Expect(tokenResp.TokenType).To(Equal("bearer"))
				Expect(tokenResp.ExpiresIn).To(Equal(43200))
				Expect(tokenResp.Scope).To(ConsistOf("bosh.admin"))
			})

			It("should successfully return tokens with Basic Auth credentials", func() {
				// Setup mock expectations
				mockJWTManager.EXPECT().
					CreateAccessToken(gomock.Any(), "admin", "bosh_cli", []string{"bosh.admin"}).
					Return("access-token-123", nil)

				mockJWTManager.EXPECT().
					CreateRefreshToken(gomock.Any(), "admin", "bosh_cli").
					Return("refresh-token-456", nil)

				// Create request with Basic Auth
				form := url.Values{}
				form.Set("grant_type", "password")
				form.Set("username", "admin")
				form.Set("password", "admin-password")
				form.Set("scope", "bosh.admin")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Add Basic Auth header
				basicAuth := base64.StdEncoding.EncodeToString([]byte("bosh_cli:bosh-secret"))
				req.Header.Set("Authorization", "Basic "+basicAuth)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var tokenResp auth.TokenResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &tokenResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokenResp.AccessToken).To(Equal("access-token-123"))
				Expect(tokenResp.RefreshToken).To(Equal("refresh-token-456"))
			})

			It("should handle multiple scopes separated by spaces", func() {
				// Setup mock expectations
				mockJWTManager.EXPECT().
					CreateAccessToken(gomock.Any(), "admin", "bosh_cli", []string{"bosh.admin", "bosh.read"}).
					Return("access-token-123", nil)

				mockJWTManager.EXPECT().
					CreateRefreshToken(gomock.Any(), "admin", "bosh_cli").
					Return("refresh-token-456", nil)

				// Create request
				form := url.Values{}
				form.Set("grant_type", "password")
				form.Set("client_id", "bosh_cli")
				form.Set("client_secret", "bosh-secret")
				form.Set("username", "admin")
				form.Set("password", "admin-password")
				form.Set("scope", "bosh.admin bosh.read")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))
			})

			It("should return error when client credentials are invalid", func() {
				// Create request with invalid client secret
				form := url.Values{}
				form.Set("grant_type", "password")
				form.Set("client_id", "bosh_cli")
				form.Set("client_secret", "wrong-secret")
				form.Set("username", "admin")
				form.Set("password", "admin-password")
				form.Set("scope", "bosh.admin")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})

			It("should return error when user credentials are invalid", func() {
				// Create request with invalid password
				form := url.Values{}
				form.Set("grant_type", "password")
				form.Set("client_id", "bosh_cli")
				form.Set("client_secret", "bosh-secret")
				form.Set("username", "admin")
				form.Set("password", "wrong-password")
				form.Set("scope", "bosh.admin")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidGrant))
			})

			It("should return error when username is missing", func() {
				// Create request without username
				form := url.Values{}
				form.Set("grant_type", "password")
				form.Set("client_id", "bosh_cli")
				form.Set("client_secret", "bosh-secret")
				form.Set("password", "admin-password")
				form.Set("scope", "bosh.admin")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidRequest))
			})
		})

		Context("with refresh_token grant type", func() {
			It("should successfully return new access token", func() {
				// Setup mock expectations
				mockJWTManager.EXPECT().
					ValidateToken("valid-refresh-token").
					Return(&auth.Claims{
						UserID:   "d788455f-4dfc-5d6f-8059-1b3a228f2cba", // UUID v5 for "admin" with UAA-Lite namespace
						UserName: "admin",
						ClientID: "bosh_cli",
						Scope:    []string{}, // Refresh tokens have no scopes
					}, nil)

				mockJWTManager.EXPECT().
					CreateAccessToken("d788455f-4dfc-5d6f-8059-1b3a228f2cba", "admin", "bosh_cli", []string{"bosh.admin"}).
					Return("new-access-token", nil)

				// Create request
				form := url.Values{}
				form.Set("grant_type", "refresh_token")
				form.Set("client_id", "bosh_cli")
				form.Set("client_secret", "bosh-secret")
				form.Set("refresh_token", "valid-refresh-token")
				form.Set("scope", "bosh.admin")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var tokenResp auth.TokenResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &tokenResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokenResp.AccessToken).To(Equal("new-access-token"))
				Expect(tokenResp.RefreshToken).To(Equal("valid-refresh-token")) // Should reuse existing token
				Expect(tokenResp.TokenType).To(Equal("bearer"))
				Expect(tokenResp.Scope).To(ConsistOf("bosh.admin"))
			})

			It("should return error when refresh_token is missing", func() {
				// Create request without refresh_token
				form := url.Values{}
				form.Set("grant_type", "refresh_token")
				form.Set("client_id", "bosh_cli")
				form.Set("client_secret", "bosh-secret")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidRequest))
			})

			It("should return error when refresh_token is invalid", func() {
				// Setup mock to return error for invalid token
				mockJWTManager.EXPECT().
					ValidateToken("invalid-refresh-token").
					Return(nil, fmt.Errorf("token is expired or invalid"))

				// Create request
				form := url.Values{}
				form.Set("grant_type", "refresh_token")
				form.Set("client_id", "bosh_cli")
				form.Set("client_secret", "bosh-secret")
				form.Set("refresh_token", "invalid-refresh-token")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidGrant))
			})
		})

		Context("with client_credentials grant type", func() {
			It("should successfully return access token without refresh token", func() {
				// Setup mock expectations
				mockJWTManager.EXPECT().
					CreateAccessToken("service_client", "", "service_client", []string{"uaa.resource", "clients.read"}).
					Return("access-token-123", nil)

				// Create request
				form := url.Values{}
				form.Set("grant_type", "client_credentials")
				form.Set("client_id", "service_client")
				form.Set("client_secret", "service-secret")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var tokenResp auth.TokenResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &tokenResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokenResp.AccessToken).To(Equal("access-token-123"))
				Expect(tokenResp.RefreshToken).To(BeEmpty()) // No refresh token for client_credentials
				Expect(tokenResp.TokenType).To(Equal("bearer"))
				Expect(tokenResp.Scope).To(ConsistOf("uaa.resource", "clients.read"))
			})

			It("should return error when client is not authorized for client_credentials", func() {
				// Create request with client that doesn't have client_credentials grant
				form := url.Values{}
				form.Set("grant_type", "client_credentials")
				form.Set("client_id", "bosh_cli")
				form.Set("client_secret", "bosh-secret")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorUnauthorizedClient))
			})
		})

		Context("with unsupported grant type", func() {
			It("should return unsupported_grant_type error", func() {
				// Create request with unsupported grant type
				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("client_id", "bosh_cli")
				form.Set("client_secret", "bosh-secret")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorUnsupportedGrantType))
			})
		})

		Context("with missing grant_type", func() {
			It("should return invalid_request error", func() {
				// Create request without grant_type
				form := url.Values{}
				form.Set("client_id", "bosh_cli")
				form.Set("client_secret", "bosh-secret")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidRequest))
				Expect(oauth2Err.ErrorDescription).To(ContainSubstring("grant_type"))
			})
		})

		Context("with invalid HTTP method", func() {
			It("should return 405 Method Not Allowed for GET", func() {
				req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidRequest))
			})

			It("should return 405 Method Not Allowed for PUT", func() {
				req := httptest.NewRequest(http.MethodPut, "/oauth/token", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})
		})

		Context("with malformed request body", func() {
			It("should return invalid_request error", func() {
				// Create request with invalid content type
				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("not-valid-form-data"))
				req.Header.Set("Content-Type", "application/json")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidRequest))
			})
		})

		Context("with malformed Basic Auth", func() {
			It("should return error for invalid base64", func() {
				// Create request with invalid Base64 in Authorization header
				form := url.Values{}
				form.Set("grant_type", "password")
				form.Set("username", "admin")
				form.Set("password", "admin-password")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Authorization", "Basic invalid-base64!!!")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})

			It("should return error for malformed Basic Auth format", func() {
				// Create request with valid Base64 but invalid format (no colon)
				form := url.Values{}
				form.Set("grant_type", "password")
				form.Set("username", "admin")
				form.Set("password", "admin-password")

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Encode "noclientid" without a colon separator
				basicAuth := base64.StdEncoding.EncodeToString([]byte("noclientsecret"))
				req.Header.Set("Authorization", "Basic "+basicAuth)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidClient))
			})
		})

		Context("when scope is empty", func() {
			It("should use default scopes from user and client", func() {
				// Setup mock expectations - the grant handler will calculate default scopes
				mockJWTManager.EXPECT().
					CreateAccessToken(gomock.Any(), "admin", "bosh_cli", gomock.Any()).
					Return("access-token-123", nil)

				mockJWTManager.EXPECT().
					CreateRefreshToken(gomock.Any(), "admin", "bosh_cli").
					Return("refresh-token-456", nil)

				// Create request without scope parameter
				form := url.Values{}
				form.Set("grant_type", "password")
				form.Set("client_id", "bosh_cli")
				form.Set("client_secret", "bosh-secret")
				form.Set("username", "admin")
				form.Set("password", "admin-password")
				// No scope parameter

				req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))
			})
		})
	})
})

// Test configuration YAML
const tokenHandlerTestConfigYAML = `
server:
  port: 8443
  issuer: "https://uaa.test.com:8443/oauth/token"

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
  active_key_id: "test-key-1"
  access_token_validity: 43200
  refresh_token_validity: 2592000
  keys:
    test-key-1:
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
      - "password"
      - "refresh_token"
    scope:
      - "bosh.admin"
      - "bosh.read"
    authorities:
      - "bosh.admin"
    access_token_validity: 43200
    refresh_token_validity: 2592000

  config_server:
    secret: "config-secret"
    authorized_grant_types:
      - "password"
      - "refresh_token"
    scope:
      - "config.admin"
    authorities:
      - "config.admin"
    access_token_validity: 7200

  service_client:
    secret: "service-secret"
    authorized_grant_types:
      - "client_credentials"
    scope:
      - "openid"
    authorities:
      - "uaa.resource"
      - "clients.read"

users:
  admin:
    password: "admin-password"
    email: "admin@example.com"
    groups:
      - "bosh.admin"
      - "bosh.read"
      - "config.admin"
`
