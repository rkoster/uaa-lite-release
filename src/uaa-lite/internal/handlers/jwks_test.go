package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/cloudfoundry/uaa-lite/internal/auth"
	"github.com/cloudfoundry/uaa-lite/internal/auth/mocks"
	"github.com/cloudfoundry/uaa-lite/internal/handlers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("JWKSHandler", func() {
	var (
		handler        *handlers.JWKSHandler
		mockJWTManager *mocks.MockJWTManager
		ctrl           *gomock.Controller
		recorder       *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		// Create mock JWT manager
		ctrl = gomock.NewController(GinkgoT())
		mockJWTManager = mocks.NewMockJWTManager(ctrl)

		// Create handler
		handler = handlers.NewJWKSHandler(mockJWTManager)

		// Create response recorder
		recorder = httptest.NewRecorder()
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("ServeHTTP", func() {
		Context("with valid request", func() {
			It("should return public keys in JWKS format", func() {
				// Setup mock expectations - return JWKS with one key
				expectedJWKS := map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"kid": "test-key-1",
							"use": "sig",
							"alg": "RS256",
							"n":   "base64encodedmodulus",
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

				var jwks map[string]interface{}
				err := json.Unmarshal(recorder.Body.Bytes(), &jwks)
				Expect(err).NotTo(HaveOccurred())
				Expect(jwks).To(HaveKey("keys"))

				keys, ok := jwks["keys"].([]interface{})
				Expect(ok).To(BeTrue())
				Expect(keys).To(HaveLen(1))

				key, ok := keys[0].(map[string]interface{})
				Expect(ok).To(BeTrue())
				Expect(key).To(HaveKey("kty"))
				Expect(key["kty"]).To(Equal("RSA"))
				Expect(key).To(HaveKey("kid"))
				Expect(key["kid"]).To(Equal("test-key-1"))
				Expect(key).To(HaveKey("use"))
				Expect(key["use"]).To(Equal("sig"))
				Expect(key).To(HaveKey("alg"))
				Expect(key["alg"]).To(Equal("RS256"))
				Expect(key).To(HaveKey("n"))
				Expect(key).To(HaveKey("e"))
			})

			It("should return multiple public keys in JWKS format", func() {
				// Setup mock expectations - return JWKS with multiple keys
				expectedJWKS := map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"kid": "test-key-1",
							"use": "sig",
							"alg": "RS256",
							"n":   "base64encodedmodulus1",
							"e":   "AQAB",
						},
						{
							"kty": "RSA",
							"kid": "test-key-2",
							"use": "sig",
							"alg": "RS256",
							"n":   "base64encodedmodulus2",
							"e":   "AQAB",
						},
						{
							"kty": "RSA",
							"kid": "test-key-3",
							"use": "sig",
							"alg": "RS256",
							"n":   "base64encodedmodulus3",
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

				var jwks map[string]interface{}
				err := json.Unmarshal(recorder.Body.Bytes(), &jwks)
				Expect(err).NotTo(HaveOccurred())

				keys, ok := jwks["keys"].([]interface{})
				Expect(ok).To(BeTrue())
				Expect(keys).To(HaveLen(3))

				// Verify first key
				key1, ok := keys[0].(map[string]interface{})
				Expect(ok).To(BeTrue())
				Expect(key1["kid"]).To(Equal("test-key-1"))

				// Verify second key
				key2, ok := keys[1].(map[string]interface{})
				Expect(ok).To(BeTrue())
				Expect(key2["kid"]).To(Equal("test-key-2"))

				// Verify third key
				key3, ok := keys[2].(map[string]interface{})
				Expect(ok).To(BeTrue())
				Expect(key3["kid"]).To(Equal("test-key-3"))
			})

			It("should return empty keys list when no keys are configured", func() {
				// Setup mock expectations - return empty JWKS
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

				var jwks map[string]interface{}
				err := json.Unmarshal(recorder.Body.Bytes(), &jwks)
				Expect(err).NotTo(HaveOccurred())

				keys, ok := jwks["keys"].([]interface{})
				Expect(ok).To(BeTrue())
				Expect(keys).To(HaveLen(0))
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
				Expect(errorResp["error"]).To(ContainSubstring("only GET method is allowed"))
			})

			It("should return 405 Method Not Allowed for PUT", func() {
				req := httptest.NewRequest(http.MethodPut, "/token_keys", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))

				var errorResp map[string]string
				err := json.Unmarshal(recorder.Body.Bytes(), &errorResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(errorResp).To(HaveKey("error"))
			})

			It("should return 405 Method Not Allowed for DELETE", func() {
				req := httptest.NewRequest(http.MethodDelete, "/token_keys", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})

			It("should return 405 Method Not Allowed for PATCH", func() {
				req := httptest.NewRequest(http.MethodPatch, "/token_keys", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})
		})

		Context("with retrieval errors", func() {
			It("should return 500 when GetPublicKeys fails", func() {
				// Setup mock to return error
				mockJWTManager.EXPECT().
					GetPublicKeys().
					Return(nil, auth.NewOAuth2Error("server_error", "failed to load keys"))

				// Create request
				req := httptest.NewRequest(http.MethodGet, "/token_keys", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusInternalServerError))

				var errorResp map[string]string
				err := json.Unmarshal(recorder.Body.Bytes(), &errorResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(errorResp).To(HaveKey("error"))
				Expect(errorResp["error"]).To(ContainSubstring("failed to retrieve public keys"))
			})
		})

		Context("with query parameters", func() {
			It("should ignore query parameters and return keys", func() {
				// Setup mock expectations
				expectedJWKS := map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"kid": "test-key-1",
							"use": "sig",
							"alg": "RS256",
							"n":   "base64encodedmodulus",
							"e":   "AQAB",
						},
					},
				}

				mockJWTManager.EXPECT().
					GetPublicKeys().
					Return(expectedJWKS, nil)

				// Create request with query parameters
				req := httptest.NewRequest(http.MethodGet, "/token_keys?format=json&foo=bar", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var jwks map[string]interface{}
				err := json.Unmarshal(recorder.Body.Bytes(), &jwks)
				Expect(err).NotTo(HaveOccurred())
				Expect(jwks).To(HaveKey("keys"))
			})
		})

		Context("response format validation", func() {
			It("should always return a keys array in JWKS response", func() {
				// Setup mock expectations
				expectedJWKS := map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"kid": "test-key-1",
							"use": "sig",
							"alg": "RS256",
							"n":   "base64encodedmodulus",
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

				// Ensure response is valid JSON
				var jwks map[string]interface{}
				err := json.Unmarshal(recorder.Body.Bytes(), &jwks)
				Expect(err).NotTo(HaveOccurred())

				// Ensure keys field exists and is an array
				Expect(jwks).To(HaveKey("keys"))
				keys, ok := jwks["keys"].([]interface{})
				Expect(ok).To(BeTrue())
				Expect(keys).NotTo(BeNil())
			})

			It("should include required JWK fields for each key", func() {
				// Setup mock expectations
				expectedJWKS := map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"kid": "test-key-1",
							"use": "sig",
							"alg": "RS256",
							"n":   "base64encodedmodulus",
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

				var jwks map[string]interface{}
				err := json.Unmarshal(recorder.Body.Bytes(), &jwks)
				Expect(err).NotTo(HaveOccurred())

				keys, ok := jwks["keys"].([]interface{})
				Expect(ok).To(BeTrue())
				Expect(keys).To(HaveLen(1))

				key, ok := keys[0].(map[string]interface{})
				Expect(ok).To(BeTrue())

				// Verify required fields per RFC 7517
				Expect(key).To(HaveKey("kty")) // Key Type
				Expect(key).To(HaveKey("kid")) // Key ID
				Expect(key).To(HaveKey("use")) // Public Key Use
				Expect(key).To(HaveKey("alg")) // Algorithm
				Expect(key).To(HaveKey("n"))   // Modulus (RSA)
				Expect(key).To(HaveKey("e"))   // Public Exponent (RSA)
			})
		})
	})
})
