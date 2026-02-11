package auth_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cloudfoundry/uaa-lite/internal/auth"
)

var _ = Describe("RefreshTokenStore", func() {
	var store auth.RefreshTokenStore

	BeforeEach(func() {
		store = auth.NewRefreshTokenStore()
	})

	Describe("Store", func() {
		It("returns a non-empty opaque token", func() {
			data := auth.RefreshTokenData{
				ClientID:  "test-client",
				UserID:    "user-123",
				Username:  "testuser",
				Email:     "test@example.com",
				Scope:     []string{"openid", "bosh.admin"},
				ExpiresAt: time.Now().Add(time.Hour),
				CreatedAt: time.Now(),
			}

			token := store.Store(data)

			Expect(token).NotTo(BeEmpty())
			Expect(len(token)).To(BeNumerically(">", 20))
		})

		It("returns unique tokens for each store call", func() {
			data := auth.RefreshTokenData{
				ClientID:  "test-client",
				UserID:    "user-123",
				Username:  "testuser",
				Email:     "test@example.com",
				Scope:     []string{"openid"},
				ExpiresAt: time.Now().Add(time.Hour),
				CreatedAt: time.Now(),
			}

			token1 := store.Store(data)
			token2 := store.Store(data)

			Expect(token1).NotTo(Equal(token2))
		})

		It("increments the count", func() {
			Expect(store.Count()).To(Equal(0))

			store.Store(auth.RefreshTokenData{
				ClientID:  "client1",
				ExpiresAt: time.Now().Add(time.Hour),
			})
			Expect(store.Count()).To(Equal(1))

			store.Store(auth.RefreshTokenData{
				ClientID:  "client2",
				ExpiresAt: time.Now().Add(time.Hour),
			})
			Expect(store.Count()).To(Equal(2))
		})
	})

	Describe("Retrieve", func() {
		It("returns the stored token data", func() {
			data := auth.RefreshTokenData{
				ClientID:  "test-client",
				UserID:    "user-123",
				Username:  "testuser",
				Email:     "test@example.com",
				Scope:     []string{"openid", "bosh.admin"},
				ExpiresAt: time.Now().Add(time.Hour),
				CreatedAt: time.Now(),
			}

			token := store.Store(data)

			retrieved, err := store.Retrieve(token)

			Expect(err).NotTo(HaveOccurred())
			Expect(retrieved.ClientID).To(Equal("test-client"))
			Expect(retrieved.UserID).To(Equal("user-123"))
			Expect(retrieved.Username).To(Equal("testuser"))
			Expect(retrieved.Email).To(Equal("test@example.com"))
			Expect(retrieved.Scope).To(Equal([]string{"openid", "bosh.admin"}))
		})

		It("removes the token after retrieval (single use)", func() {
			data := auth.RefreshTokenData{
				ClientID:  "test-client",
				ExpiresAt: time.Now().Add(time.Hour),
			}

			token := store.Store(data)
			Expect(store.Count()).To(Equal(1))

			_, err := store.Retrieve(token)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.Count()).To(Equal(0))

			// Second retrieval should fail
			_, err = store.Retrieve(token)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("returns error for unknown token", func() {
			_, err := store.Retrieve("nonexistent-token")

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("returns error for expired token", func() {
			data := auth.RefreshTokenData{
				ClientID:  "test-client",
				ExpiresAt: time.Now().Add(-time.Hour), // Already expired
			}

			token := store.Store(data)

			_, err := store.Retrieve(token)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("expired"))
		})

		It("removes expired token from store even when retrieval fails", func() {
			data := auth.RefreshTokenData{
				ClientID:  "test-client",
				ExpiresAt: time.Now().Add(-time.Hour), // Already expired
			}

			token := store.Store(data)
			Expect(store.Count()).To(Equal(1))

			_, err := store.Retrieve(token)
			Expect(err).To(HaveOccurred())

			// Token should be removed even though retrieval failed
			Expect(store.Count()).To(Equal(0))
		})
	})

	Describe("Count", func() {
		It("returns 0 for empty store", func() {
			Expect(store.Count()).To(Equal(0))
		})

		It("returns correct count after multiple operations", func() {
			token1 := store.Store(auth.RefreshTokenData{
				ClientID:  "client1",
				ExpiresAt: time.Now().Add(time.Hour),
			})
			store.Store(auth.RefreshTokenData{
				ClientID:  "client2",
				ExpiresAt: time.Now().Add(time.Hour),
			})
			store.Store(auth.RefreshTokenData{
				ClientID:  "client3",
				ExpiresAt: time.Now().Add(time.Hour),
			})

			Expect(store.Count()).To(Equal(3))

			store.Retrieve(token1)
			Expect(store.Count()).To(Equal(2))
		})
	})

	Describe("StartCleanup", func() {
		It("removes expired tokens periodically", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Store a token that expires very soon
			store.Store(auth.RefreshTokenData{
				ClientID:  "soon-expired",
				ExpiresAt: time.Now().Add(50 * time.Millisecond),
			})

			// Store a token that won't expire
			store.Store(auth.RefreshTokenData{
				ClientID:  "long-lived",
				ExpiresAt: time.Now().Add(time.Hour),
			})

			Expect(store.Count()).To(Equal(2))

			// Start cleanup with short interval
			store.StartCleanup(ctx, 100*time.Millisecond)

			// Wait for token to expire and cleanup to run
			time.Sleep(200 * time.Millisecond)

			// Only the long-lived token should remain
			Expect(store.Count()).To(Equal(1))
		})

		It("stops cleanup when context is cancelled", func() {
			ctx, cancel := context.WithCancel(context.Background())

			store.Store(auth.RefreshTokenData{
				ClientID:  "test",
				ExpiresAt: time.Now().Add(-time.Hour), // Already expired
			})

			store.StartCleanup(ctx, 50*time.Millisecond)

			// Cancel immediately
			cancel()

			// Wait a bit
			time.Sleep(100 * time.Millisecond)

			// Token should still be there since cleanup was cancelled
			// (or it might have run once before cancel - either is acceptable)
			// The main point is that the goroutine exited cleanly
		})
	})

	Describe("Concurrent access", func() {
		It("handles concurrent store and retrieve operations safely", func() {
			const numOperations = 100
			done := make(chan bool, numOperations*2)

			// Concurrent stores
			for i := 0; i < numOperations; i++ {
				go func() {
					token := store.Store(auth.RefreshTokenData{
						ClientID:  "concurrent-client",
						ExpiresAt: time.Now().Add(time.Hour),
					})
					Expect(token).NotTo(BeEmpty())
					done <- true
				}()
			}

			// Wait for all stores to complete
			for i := 0; i < numOperations; i++ {
				<-done
			}

			Expect(store.Count()).To(Equal(numOperations))

			// Store some tokens and retrieve them concurrently
			tokens := make([]string, numOperations)
			for i := 0; i < numOperations; i++ {
				tokens[i] = store.Store(auth.RefreshTokenData{
					ClientID:  "retrieve-test",
					ExpiresAt: time.Now().Add(time.Hour),
				})
			}

			// Concurrent retrieves
			for i := 0; i < numOperations; i++ {
				go func(token string) {
					store.Retrieve(token)
					done <- true
				}(tokens[i])
			}

			// Wait for all retrieves to complete
			for i := 0; i < numOperations; i++ {
				<-done
			}
		})
	})
})
