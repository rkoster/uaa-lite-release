package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/cloudfoundry/uaa-lite/internal/handlers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HealthHandler", func() {
	var (
		handler  *handlers.HealthHandler
		recorder *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		// Create handler
		handler = handlers.NewHealthHandler()

		// Create response recorder
		recorder = httptest.NewRecorder()
	})

	Describe("ServeHTTP", func() {
		Context("with valid GET request", func() {
			It("should return 200 OK with healthy status", func() {
				// Create request
				req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))
				Expect(recorder.Header().Get("Content-Type")).To(Equal("application/json"))

				var healthResp handlers.HealthResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &healthResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(healthResp.Status).To(Equal("ok"))
			})

			It("should return valid JSON", func() {
				// Create request
				req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				// Ensure response is valid JSON
				var healthResp map[string]interface{}
				err := json.Unmarshal(recorder.Body.Bytes(), &healthResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(healthResp).To(HaveKey("status"))
				Expect(healthResp["status"]).To(Equal("ok"))
			})

			It("should return consistent status across multiple requests", func() {
				// Make first request
				req1 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
				recorder1 := httptest.NewRecorder()
				handler.ServeHTTP(recorder1, req1)

				var healthResp1 handlers.HealthResponse
				err := json.Unmarshal(recorder1.Body.Bytes(), &healthResp1)
				Expect(err).NotTo(HaveOccurred())

				// Make second request
				req2 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
				recorder2 := httptest.NewRecorder()
				handler.ServeHTTP(recorder2, req2)

				var healthResp2 handlers.HealthResponse
				err = json.Unmarshal(recorder2.Body.Bytes(), &healthResp2)
				Expect(err).NotTo(HaveOccurred())

				// Both should have same status
				Expect(healthResp1.Status).To(Equal(healthResp2.Status))
				Expect(healthResp1.Status).To(Equal("ok"))
				Expect(healthResp2.Status).To(Equal("ok"))
			})
		})

		Context("with invalid HTTP method", func() {
			It("should return 405 Method Not Allowed for POST", func() {
				req := httptest.NewRequest(http.MethodPost, "/healthz", nil)

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
				req := httptest.NewRequest(http.MethodPut, "/healthz", nil)

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
				req := httptest.NewRequest(http.MethodDelete, "/healthz", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})

			It("should return 405 Method Not Allowed for PATCH", func() {
				req := httptest.NewRequest(http.MethodPatch, "/healthz", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})

			It("should return 405 Method Not Allowed for HEAD", func() {
				req := httptest.NewRequest(http.MethodHead, "/healthz", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})

			It("should return 405 Method Not Allowed for OPTIONS", func() {
				req := httptest.NewRequest(http.MethodOptions, "/healthz", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify error response
				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})
		})

		Context("with query parameters", func() {
			It("should ignore query parameters and return healthy status", func() {
				// Create request with query parameters
				req := httptest.NewRequest(http.MethodGet, "/healthz?verbose=true&format=json", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var healthResp handlers.HealthResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &healthResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(healthResp.Status).To(Equal("ok"))
			})
		})

		Context("with request headers", func() {
			It("should ignore Accept header and return JSON", func() {
				// Create request with custom Accept header
				req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
				req.Header.Set("Accept", "text/plain")

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response is still JSON
				Expect(recorder.Code).To(Equal(http.StatusOK))
				Expect(recorder.Header().Get("Content-Type")).To(Equal("application/json"))

				var healthResp handlers.HealthResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &healthResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(healthResp.Status).To(Equal("ok"))
			})

			It("should set proper Content-Type header", func() {
				// Create request
				req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify Content-Type header
				Expect(recorder.Code).To(Equal(http.StatusOK))
				Expect(recorder.Header().Get("Content-Type")).To(Equal("application/json"))
			})
		})

		Context("response format", func() {
			It("should always return status field", func() {
				// Create request
				req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var healthResp handlers.HealthResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &healthResp)
				Expect(err).NotTo(HaveOccurred())

				// Status field should exist and have correct value
				Expect(healthResp.Status).NotTo(BeEmpty())
				Expect(healthResp.Status).To(Equal("ok"))
			})

			It("should not have any additional fields in response", func() {
				// Create request
				req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

				// Handle request
				handler.ServeHTTP(recorder, req)

				// Verify response
				Expect(recorder.Code).To(Equal(http.StatusOK))

				var healthResp map[string]interface{}
				err := json.Unmarshal(recorder.Body.Bytes(), &healthResp)
				Expect(err).NotTo(HaveOccurred())

				// Should only have status field
				Expect(healthResp).To(HaveLen(1))
				Expect(healthResp).To(HaveKey("status"))
			})
		})
	})
})
