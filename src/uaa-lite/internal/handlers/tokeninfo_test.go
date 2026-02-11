package handlers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/cloudfoundry/uaa-lite/internal/auth"
	"github.com/cloudfoundry/uaa-lite/internal/auth/mocks"
	"github.com/cloudfoundry/uaa-lite/internal/handlers"
	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("TokenInfoHandler", func() {
	var (
		handler        *handlers.TokenInfoHandler
		mockJWTManager *mocks.MockJWTManager
		ctrl           *gomock.Controller
		recorder       *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		// Create mock JWT manager
		ctrl = gomock.NewController(GinkgoT())
		mockJWTManager = mocks.NewMockJWTManager(ctrl)

		// Create handler
		handler = handlers.NewTokenInfoHandler(mockJWTManager)

		// Create response recorder
		recorder = httptest.NewRecorder()
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("ServeHTTP", func() {
		Context("with valid token", func() {
			It("should return token information", func() {
				// Setup mock expectations
				mockJWTManager.EXPECT().
					ValidateToken("valid-token").
					Return(&auth.Claims{
						UserID:   "d788455f-4dfc-5d6f-8059-1b3a228f2cba",
						UserName: "admin",
						Email:    "admin@example.com",
						ClientID: "bosh_cli",
						Scope:    []string{"bosh.admin", "bosh.read"},
						RegisteredClaims: jwt.RegisteredClaims{
							Issuer:    "https://uaa.test.com:8443/oauth/token",
							ExpiresAt: &jwt.NumericDate{Time: time.Unix(1234567890, 0)},
							Audience:  []string{"bosh"},
						},
					}, nil)

				// Create request
				form := url.Values{}
				form.Set("token", "valid-token")

				req := httptest.NewRequest(http.MethodPost, "/oauth/check_token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))
				Expect(recorder.Header().Get("Content-Type")).To(Equal("application/json"))

				var tokenInfo handlers.TokenInfo
				err := json.Unmarshal(recorder.Body.Bytes(), &tokenInfo)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokenInfo.UserID).To(Equal("d788455f-4dfc-5d6f-8059-1b3a228f2cba"))
				Expect(tokenInfo.UserName).To(Equal("admin"))
				Expect(tokenInfo.Email).To(Equal("admin@example.com"))
				Expect(tokenInfo.ClientID).To(Equal("bosh_cli"))
				Expect(tokenInfo.Scope).To(ConsistOf("bosh.admin", "bosh.read"))
				Expect(tokenInfo.Exp).To(Equal(int64(1234567890)))
				Expect(tokenInfo.Iss).To(Equal("https://uaa.test.com:8443/oauth/token"))
				Expect(tokenInfo.Aud).To(ConsistOf("bosh"))
			})

			It("should handle tokens without email", func() {
				// Setup mock expectations
				mockJWTManager.EXPECT().
					ValidateToken("token-no-email").
					Return(&auth.Claims{
						UserID:   "d788455f-4dfc-5d6f-8059-1b3a228f2cba",
						UserName: "admin",
						Email:    "", // No email
						ClientID: "bosh_cli",
						Scope:    []string{"bosh.admin"},
						RegisteredClaims: jwt.RegisteredClaims{
							Issuer:    "https://uaa.test.com:8443/oauth/token",
							ExpiresAt: &jwt.NumericDate{Time: time.Unix(1234567890, 0)},
							Audience:  []string{"bosh"},
						},
					}, nil)

				// Create request
				form := url.Values{}
				form.Set("token", "token-no-email")

				req := httptest.NewRequest(http.MethodPost, "/oauth/check_token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var tokenInfo handlers.TokenInfo
				err := json.Unmarshal(recorder.Body.Bytes(), &tokenInfo)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokenInfo.Email).To(Equal(""))
				Expect(tokenInfo.UserName).To(Equal("admin"))
			})

			It("should handle tokens with multiple audiences", func() {
				// Setup mock expectations
				mockJWTManager.EXPECT().
					ValidateToken("multi-aud-token").
					Return(&auth.Claims{
						UserID:   "d788455f-4dfc-5d6f-8059-1b3a228f2cba",
						UserName: "admin",
						Email:    "admin@example.com",
						ClientID: "admin_cli",
						Scope:    []string{"bosh.admin", "config.admin"},
						RegisteredClaims: jwt.RegisteredClaims{
							Issuer:    "https://uaa.test.com:8443/oauth/token",
							ExpiresAt: &jwt.NumericDate{Time: time.Unix(1234567890, 0)},
							Audience:  []string{"bosh", "config"},
						},
					}, nil)

				// Create request
				form := url.Values{}
				form.Set("token", "multi-aud-token")

				req := httptest.NewRequest(http.MethodPost, "/oauth/check_token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var tokenInfo handlers.TokenInfo
				err := json.Unmarshal(recorder.Body.Bytes(), &tokenInfo)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokenInfo.Aud).To(ConsistOf("bosh", "config"))
				Expect(tokenInfo.Scope).To(ConsistOf("bosh.admin", "config.admin"))
			})
		})

		Context("with invalid token", func() {
			It("should return error when token is invalid", func() {
				// Setup mock to return error for invalid token
				mockJWTManager.EXPECT().
					ValidateToken("invalid-token").
					Return(nil, fmt.Errorf("invalid token signature"))

				// Create request
				form := url.Values{}
				form.Set("token", "invalid-token")

				req := httptest.NewRequest(http.MethodPost, "/oauth/check_token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidRequest))
				Expect(oauth2Err.ErrorDescription).To(ContainSubstring("invalid or expired token"))
			})

			It("should return error when token is expired", func() {
				// Setup mock to return error for expired token
				mockJWTManager.EXPECT().
					ValidateToken("expired-token").
					Return(nil, fmt.Errorf("token is expired"))

				// Create request
				form := url.Values{}
				form.Set("token", "expired-token")

				req := httptest.NewRequest(http.MethodPost, "/oauth/check_token", strings.NewReader(form.Encode()))
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

		Context("with missing token parameter", func() {
			It("should return error when token is missing", func() {
				// Create request without token parameter
				form := url.Values{}

				req := httptest.NewRequest(http.MethodPost, "/oauth/check_token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidRequest))
				Expect(oauth2Err.ErrorDescription).To(ContainSubstring("token is required"))
			})

			It("should return error when token parameter is empty", func() {
				// Create request with empty token parameter
				form := url.Values{}
				form.Set("token", "")

				req := httptest.NewRequest(http.MethodPost, "/oauth/check_token", strings.NewReader(form.Encode()))
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

		Context("with invalid HTTP method", func() {
			It("should return 405 Method Not Allowed for GET", func() {
				req := httptest.NewRequest(http.MethodGet, "/oauth/check_token", nil)

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
				req := httptest.NewRequest(http.MethodPut, "/oauth/check_token", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidRequest))
			})

			It("should return 405 Method Not Allowed for DELETE", func() {
				req := httptest.NewRequest(http.MethodDelete, "/oauth/check_token", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})
		})

		Context("with malformed request body", func() {
			It("should return error for missing token when JSON body is sent", func() {
				// Create request with JSON content type - ParseForm won't fail but will return no fields
				req := httptest.NewRequest(http.MethodPost, "/oauth/check_token", strings.NewReader(`{"token":"value"}`))
				req.Header.Set("Content-Type", "application/json")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response - should fail because token parameter is missing
				Expect(recorder.Code).To(Equal(http.StatusBadRequest))

				var oauth2Err auth.OAuth2Error
				err := json.Unmarshal(recorder.Body.Bytes(), &oauth2Err)
				Expect(err).NotTo(HaveOccurred())
				Expect(oauth2Err.ErrorCode).To(Equal(auth.ErrorInvalidRequest))
				Expect(oauth2Err.ErrorDescription).To(ContainSubstring("token is required"))
			})
		})

		Context("with tokens containing no scopes", func() {
			It("should handle tokens with empty scope list", func() {
				// Setup mock expectations
				mockJWTManager.EXPECT().
					ValidateToken("no-scope-token").
					Return(&auth.Claims{
						UserID:   "d788455f-4dfc-5d6f-8059-1b3a228f2cba",
						UserName: "admin",
						Email:    "admin@example.com",
						ClientID: "bosh_cli",
						Scope:    []string{}, // No scopes
						RegisteredClaims: jwt.RegisteredClaims{
							Issuer:    "https://uaa.test.com:8443/oauth/token",
							ExpiresAt: &jwt.NumericDate{Time: time.Unix(1234567890, 0)},
							Audience:  []string{}, // No audience
						},
					}, nil)

				// Create request
				form := url.Values{}
				form.Set("token", "no-scope-token")

				req := httptest.NewRequest(http.MethodPost, "/oauth/check_token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var tokenInfo handlers.TokenInfo
				err := json.Unmarshal(recorder.Body.Bytes(), &tokenInfo)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokenInfo.Scope).To(BeEmpty())
				Expect(tokenInfo.Aud).To(BeEmpty())
			})
		})
	})
})
