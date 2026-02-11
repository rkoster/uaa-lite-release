package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/cloudfoundry/uaa-lite/internal/auth/mocks"
	"github.com/cloudfoundry/uaa-lite/internal/handlers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

// Real RSA modulus from test certificate in config/generate_test_keys.go
const testModulus = "vnulvHSh5PdsdsvwsjYfbd2bh-Y9DQPRv1dFpovUkpu5Bpw1mN6AJyy1ttYTeZ0_AP3NPhoF9KtapgkhLGDB2euBxIAcv4Zap1izeNkdokZFoFHbR3ciiQ4qDJb_Md8Hxh-pbTx9ue5YRDX7D8A354J1txigGYS4IvJnbKlnps18VFtlMt7p19dr62WbT13d6ZHv5VFVRGw1-HudCbzTRqTq3YK4fbDooYvHzPCXbBNhh8_uZaqy_wqCK0MDn8-J-iTF1EAGnD1M6mSn7ogwsPrfLxuB93xCelgklZfKnt-rPzVsArwDPQ39tqRK7oZ6CFzM2L76uL2GehRuLj5UoQ"

var _ = Describe("TokenKeyHandler", func() {
	var (
		handler        *handlers.TokenKeyHandler
		mockJWTManager *mocks.MockJWTManager
		ctrl           *gomock.Controller
		recorder       *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		// Create mock JWT manager
		ctrl = gomock.NewController(GinkgoT())
		mockJWTManager = mocks.NewMockJWTManager(ctrl)

		// Create handler
		handler = handlers.NewTokenKeyHandler(mockJWTManager, nil)

		// Create response recorder
		recorder = httptest.NewRecorder()
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("ServeHTTP", func() {
		Context("with valid GET request", func() {
			It("should return active key in JWK format with PEM encoding", func() {
				// Setup mock expectations - return JWKS with one key
				expectedJWKS := map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"kid": "test-key-1",
							"use": "sig",
							"alg": "RS256",
							"n":   testModulus,
							"e":   "AQAB",
						},
					},
				}

				mockJWTManager.EXPECT().
					GetPublicKeys().
					Return(expectedJWKS, nil)

				// Create request
				req := httptest.NewRequest(http.MethodGet, "/token_key", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))
				Expect(recorder.Header().Get("Content-Type")).To(Equal("application/json"))

				var keyResp handlers.PublicKeyJWK
				err := json.Unmarshal(recorder.Body.Bytes(), &keyResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(keyResp.Kty).To(Equal("RSA"))
				Expect(keyResp.Kid).To(Equal("test-key-1"))
				Expect(keyResp.Use).To(Equal("sig"))
				Expect(keyResp.Alg).To(Equal("RS256"))
				Expect(keyResp.N).To(Equal(testModulus))
				Expect(keyResp.E).To(Equal("AQAB"))
				// Verify PEM encoding is present and valid
				Expect(keyResp.Value).To(ContainSubstring("-----BEGIN PUBLIC KEY-----"))
				Expect(keyResp.Value).To(ContainSubstring("-----END PUBLIC KEY-----"))
			})

			It("should return valid PEM encoding", func() {
				// Setup mock expectations
				expectedJWKS := map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"kid": "test-key-1",
							"use": "sig",
							"alg": "RS256",
							"n":   testModulus,
							"e":   "AQAB",
						},
					},
				}

				mockJWTManager.EXPECT().
					GetPublicKeys().
					Return(expectedJWKS, nil)

				// Create request
				req := httptest.NewRequest(http.MethodGet, "/token_key", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var keyResp handlers.PublicKeyJWK
				err := json.Unmarshal(recorder.Body.Bytes(), &keyResp)
				Expect(err).NotTo(HaveOccurred())

				// Verify PEM structure
				Expect(keyResp.Value).To(ContainSubstring("-----BEGIN PUBLIC KEY-----"))
				Expect(keyResp.Value).To(ContainSubstring("-----END PUBLIC KEY-----"))
				// Verify PEM is not empty and has reasonable length (200+ chars)
				Expect(len(keyResp.Value)).To(BeNumerically(">", 200))
			})
		})

		Context("with invalid HTTP method", func() {
			It("should return 405 Method Not Allowed for POST", func() {
				req := httptest.NewRequest(http.MethodPost, "/token_key", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))

				var errorResp map[string]string
				err := json.Unmarshal(recorder.Body.Bytes(), &errorResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(errorResp).To(HaveKey("error"))
			})

			It("should return 405 Method Not Allowed for PUT", func() {
				req := httptest.NewRequest(http.MethodPut, "/token_key", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})

			It("should return 405 Method Not Allowed for DELETE", func() {
				req := httptest.NewRequest(http.MethodDelete, "/token_key", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})
		})

		Context("response format validation", func() {
			It("should include all required JWK fields", func() {
				// Setup mock expectations
				expectedJWKS := map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"kid": "test-key-1",
							"use": "sig",
							"alg": "RS256",
							"n":   testModulus,
							"e":   "AQAB",
						},
					},
				}

				mockJWTManager.EXPECT().
					GetPublicKeys().
					Return(expectedJWKS, nil)

				// Create request
				req := httptest.NewRequest(http.MethodGet, "/token_key", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var keyResp handlers.PublicKeyJWK
				err := json.Unmarshal(recorder.Body.Bytes(), &keyResp)
				Expect(err).NotTo(HaveOccurred())

				// Verify all required fields
				Expect(keyResp.Kty).NotTo(BeEmpty())
				Expect(keyResp.Alg).NotTo(BeEmpty())
				Expect(keyResp.Use).NotTo(BeEmpty())
				Expect(keyResp.Kid).NotTo(BeEmpty())
				Expect(keyResp.N).NotTo(BeEmpty())
				Expect(keyResp.E).NotTo(BeEmpty())
				Expect(keyResp.Value).NotTo(BeEmpty())
			})
		})
	})
})

var _ = Describe("TokenKeysHandler", func() {
	var (
		handler        *handlers.TokenKeysHandler
		mockJWTManager *mocks.MockJWTManager
		ctrl           *gomock.Controller
		recorder       *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		// Create mock JWT manager
		ctrl = gomock.NewController(GinkgoT())
		mockJWTManager = mocks.NewMockJWTManager(ctrl)

		// Create handler
		handler = handlers.NewTokenKeysHandler(mockJWTManager, nil)

		// Create response recorder
		recorder = httptest.NewRecorder()
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("ServeHTTP", func() {
		Context("with valid GET request", func() {
			It("should return all keys in JWKS format with PEM encoding", func() {
				// Setup mock expectations
				expectedJWKS := map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"kid": "test-key-1",
							"use": "sig",
							"alg": "RS256",
							"n":   testModulus,
							"e":   "AQAB",
						},
						{
							"kty": "RSA",
							"kid": "test-key-2",
							"use": "sig",
							"alg": "RS256",
							"n":   testModulus,
							"e":   "AQAB",
						},
					},
				}

				mockJWTManager.EXPECT().
					GetPublicKeys().
					Return(expectedJWKS, nil)

				// Create request
				req := httptest.NewRequest(http.MethodGet, "/token_keys", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))
				Expect(recorder.Header().Get("Content-Type")).To(Equal("application/json"))

				var jwksResp handlers.PublicKeysJWKS
				err := json.Unmarshal(recorder.Body.Bytes(), &jwksResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(jwksResp.Keys).To(HaveLen(2))
				Expect(jwksResp.Keys[0].Kid).To(Equal("test-key-1"))
				Expect(jwksResp.Keys[1].Kid).To(Equal("test-key-2"))

				// Verify PEM encoding is present
				Expect(jwksResp.Keys[0].Value).To(ContainSubstring("-----BEGIN PUBLIC KEY-----"))
				Expect(jwksResp.Keys[1].Value).To(ContainSubstring("-----BEGIN PUBLIC KEY-----"))
			})

			It("should handle empty keys list", func() {
				// Setup mock expectations - return empty keys
				expectedJWKS := map[string]interface{}{
					"keys": []map[string]interface{}{},
				}

				mockJWTManager.EXPECT().
					GetPublicKeys().
					Return(expectedJWKS, nil)

				// Create request
				req := httptest.NewRequest(http.MethodGet, "/token_keys", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var jwksResp handlers.PublicKeysJWKS
				err := json.Unmarshal(recorder.Body.Bytes(), &jwksResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(jwksResp.Keys).To(HaveLen(0))
			})
		})

		Context("with invalid HTTP method", func() {
			It("should return 405 Method Not Allowed for POST", func() {
				req := httptest.NewRequest(http.MethodPost, "/token_keys", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))

				var errorResp map[string]string
				err := json.Unmarshal(recorder.Body.Bytes(), &errorResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(errorResp).To(HaveKey("error"))
			})

			It("should return 405 Method Not Allowed for PUT", func() {
				req := httptest.NewRequest(http.MethodPut, "/token_keys", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})

			It("should return 405 Method Not Allowed for DELETE", func() {
				req := httptest.NewRequest(http.MethodDelete, "/token_keys", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})
		})

		Context("response format validation", func() {
			It("should always return keys array", func() {
				// Setup mock expectations
				expectedJWKS := map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"kid": "test-key-1",
							"use": "sig",
							"alg": "RS256",
							"n":   testModulus,
							"e":   "AQAB",
						},
					},
				}

				mockJWTManager.EXPECT().
					GetPublicKeys().
					Return(expectedJWKS, nil)

				// Create request
				req := httptest.NewRequest(http.MethodGet, "/token_keys", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var jwksResp handlers.PublicKeysJWKS
				err := json.Unmarshal(recorder.Body.Bytes(), &jwksResp)
				Expect(err).NotTo(HaveOccurred())

				// Should have keys field
				Expect(jwksResp.Keys).NotTo(BeNil())
			})

			It("should include all required fields in each key", func() {
				// Setup mock expectations
				expectedJWKS := map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"kid": "test-key-1",
							"use": "sig",
							"alg": "RS256",
							"n":   testModulus,
							"e":   "AQAB",
						},
					},
				}

				mockJWTManager.EXPECT().
					GetPublicKeys().
					Return(expectedJWKS, nil)

				// Create request
				req := httptest.NewRequest(http.MethodGet, "/token_keys", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var jwksResp handlers.PublicKeysJWKS
				err := json.Unmarshal(recorder.Body.Bytes(), &jwksResp)
				Expect(err).NotTo(HaveOccurred())

				// Verify each key has required fields
				for _, key := range jwksResp.Keys {
					Expect(key.Kty).NotTo(BeEmpty())
					Expect(key.Alg).NotTo(BeEmpty())
					Expect(key.Use).NotTo(BeEmpty())
					Expect(key.Kid).NotTo(BeEmpty())
					Expect(key.N).NotTo(BeEmpty())
					Expect(key.E).NotTo(BeEmpty())
					Expect(key.Value).NotTo(BeEmpty())
				}
			})
		})
	})
})
