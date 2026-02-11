package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/cloudfoundry/uaa-lite/internal/handlers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("InfoHandler", func() {
	var (
		handler  *handlers.InfoHandler
		recorder *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		// Create handler with test issuer URL
		handler = handlers.NewInfoHandler("https://uaa.example.com:8443")

		// Create response recorder
		recorder = httptest.NewRecorder()
	})

	Describe("ServeHTTP", func() {
		Context("with valid GET request", func() {
			It("should return 200 OK", func() {
				req := httptest.NewRequest(http.MethodGet, "/info", nil)

				handler.ServeHTTP(recorder, req)

				Expect(recorder.Code).To(Equal(http.StatusOK))
			})

			It("should return JSON content type", func() {
				req := httptest.NewRequest(http.MethodGet, "/info", nil)

				handler.ServeHTTP(recorder, req)

				Expect(recorder.Header().Get("Content-Type")).To(Equal("application/json"))
			})

			It("should return info response with all required fields", func() {
				req := httptest.NewRequest(http.MethodGet, "/info", nil)

				handler.ServeHTTP(recorder, req)

				var resp handlers.InfoResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &resp)
				Expect(err).NotTo(HaveOccurred())

				// Verify app version
				Expect(resp.App.Version).To(Equal("1.0.0"))

				// Verify links
				Expect(resp.Links.UAA).To(Equal("https://uaa.example.com:8443"))
				Expect(resp.Links.Login).To(Equal("https://uaa.example.com:8443"))

				// Verify zone name
				Expect(resp.ZoneName).To(Equal("uaa"))

				// Verify entity ID matches issuer URL
				Expect(resp.EntityID).To(Equal("https://uaa.example.com:8443"))
			})

			It("should include login prompts", func() {
				req := httptest.NewRequest(http.MethodGet, "/info", nil)

				handler.ServeHTTP(recorder, req)

				var resp handlers.InfoResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &resp)
				Expect(err).NotTo(HaveOccurred())

				// Verify prompts structure
				Expect(resp.Prompts).To(HaveKey("username"))
				Expect(resp.Prompts).To(HaveKey("password"))

				// Verify username prompt format [type, display_name]
				Expect(resp.Prompts["username"]).To(HaveLen(2))
				Expect(resp.Prompts["username"][0]).To(Equal("text"))
				Expect(resp.Prompts["username"][1]).To(Equal("Username"))

				// Verify password prompt format [type, display_name]
				Expect(resp.Prompts["password"]).To(HaveLen(2))
				Expect(resp.Prompts["password"][0]).To(Equal("password"))
				Expect(resp.Prompts["password"][1]).To(Equal("Password"))
			})
		})

		Context("with different issuer URLs", func() {
			It("should use the provided issuer URL in links and entity ID", func() {
				handlerWithDifferentIssuer := handlers.NewInfoHandler("https://uaa-prod.example.org:8443")
				recorder := httptest.NewRecorder()

				req := httptest.NewRequest(http.MethodGet, "/info", nil)
				handlerWithDifferentIssuer.ServeHTTP(recorder, req)

				var resp handlers.InfoResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &resp)
				Expect(err).NotTo(HaveOccurred())

				Expect(resp.Links.UAA).To(Equal("https://uaa-prod.example.org:8443"))
				Expect(resp.Links.Login).To(Equal("https://uaa-prod.example.org:8443"))
				Expect(resp.EntityID).To(Equal("https://uaa-prod.example.org:8443"))
			})
		})

		Context("with invalid HTTP method", func() {
			It("should return 405 Method Not Allowed for POST", func() {
				req := httptest.NewRequest(http.MethodPost, "/info", nil)

				handler.ServeHTTP(recorder, req)

				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})

			It("should return 405 Method Not Allowed for PUT", func() {
				req := httptest.NewRequest(http.MethodPut, "/info", nil)

				handler.ServeHTTP(recorder, req)

				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})

			It("should return 405 Method Not Allowed for DELETE", func() {
				req := httptest.NewRequest(http.MethodDelete, "/info", nil)

				handler.ServeHTTP(recorder, req)

				Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
			})

			It("should return error response for invalid method", func() {
				req := httptest.NewRequest(http.MethodPost, "/info", nil)

				handler.ServeHTTP(recorder, req)

				var errorResp map[string]string
				err := json.Unmarshal(recorder.Body.Bytes(), &errorResp)
				Expect(err).NotTo(HaveOccurred())
				Expect(errorResp).To(HaveKey("error"))
				Expect(errorResp["error"]).To(ContainSubstring("only GET method is allowed"))
			})
		})

		Context("response format validation", func() {
			It("should always return app object with version", func() {
				req := httptest.NewRequest(http.MethodGet, "/info", nil)

				handler.ServeHTTP(recorder, req)

				var resp handlers.InfoResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &resp)
				Expect(err).NotTo(HaveOccurred())

				Expect(resp.App.Version).NotTo(BeEmpty())
			})

			It("should always return links with uaa and login", func() {
				req := httptest.NewRequest(http.MethodGet, "/info", nil)

				handler.ServeHTTP(recorder, req)

				var resp handlers.InfoResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &resp)
				Expect(err).NotTo(HaveOccurred())

				Expect(resp.Links.UAA).NotTo(BeEmpty())
				Expect(resp.Links.Login).NotTo(BeEmpty())
			})

			It("should always return zone_name as 'uaa'", func() {
				req := httptest.NewRequest(http.MethodGet, "/info", nil)

				handler.ServeHTTP(recorder, req)

				var resp handlers.InfoResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &resp)
				Expect(err).NotTo(HaveOccurred())

				Expect(resp.ZoneName).To(Equal("uaa"))
			})

			It("should always have entityID set to issuer URL", func() {
				req := httptest.NewRequest(http.MethodGet, "/info", nil)

				handler.ServeHTTP(recorder, req)

				var resp handlers.InfoResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &resp)
				Expect(err).NotTo(HaveOccurred())

				Expect(resp.EntityID).To(Equal("https://uaa.example.com:8443"))
				Expect(resp.EntityID).To(Equal(resp.Links.UAA))
			})

			It("should always have username and password prompts", func() {
				req := httptest.NewRequest(http.MethodGet, "/info", nil)

				handler.ServeHTTP(recorder, req)

				var resp handlers.InfoResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &resp)
				Expect(err).NotTo(HaveOccurred())

				Expect(resp.Prompts).To(HaveKey("username"))
				Expect(resp.Prompts).To(HaveKey("password"))
				Expect(resp.Prompts).To(HaveLen(2))
			})
		})
	})
})
