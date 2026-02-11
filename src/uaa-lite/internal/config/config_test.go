package config_test

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/bcrypt"

	"github.com/cloudfoundry/uaa-lite/internal/config"
)

// Valid test TLS and JWT keys for use in test configs
const validTLSSection = `tls:
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
    -----END RSA PRIVATE KEY-----`

const validJWTSection = `jwt:
  active_key_id: "key-1"
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
        -----END RSA PRIVATE KEY-----`

var _ = Describe("Config", func() {
	var (
		tempDir    string
		configPath string
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "uaa-config-test")
		Expect(err).NotTo(HaveOccurred())
		configPath = filepath.Join(tempDir, "config.yml")
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Describe("Load", func() {
		Context("with valid configuration", func() {
			BeforeEach(func() {
				validConfig := `
server:
  port: 8443
  issuer: "https://uaa.example.com:8443"

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
  access_token_validity: 3600
  refresh_token_validity: 86400

clients:
  bosh_cli:
    secret: "bosh-cli-secret"
    authorized_grant_types:
      - password
      - refresh_token
    scope:
      - openid
      - bosh.admin
    authorities:
      - uaa.none
    access_token_validity: 600

  director:
    secret: "director-secret"
    authorized_grant_types:
      - client_credentials
    authorities:
      - bosh.admin
      - config_server.admin

users:
  admin:
    password: "admin-password"
    email: "admin@example.com"
    groups:
      - bosh.admin
      - openid
`
				err := os.WriteFile(configPath, []byte(validConfig), 0644)
				Expect(err).NotTo(HaveOccurred())
			})

			It("loads all configuration values", func() {
				cfg, err := config.Load(configPath)

				Expect(err).NotTo(HaveOccurred())
				Expect(cfg.Server.Port).To(Equal(8443))
				Expect(cfg.Server.Issuer).To(Equal("https://uaa.example.com:8443"))
				Expect(cfg.JWT.ActiveKeyID).To(Equal("key-1"))
				Expect(cfg.JWT.AccessTokenValidity).To(Equal(3600))
				Expect(cfg.Clients).To(HaveKey("bosh_cli"))
				Expect(cfg.Users).To(HaveKey("admin"))
			})

			It("hashes user passwords with bcrypt", func() {
				cfg, err := config.Load(configPath)

				Expect(err).NotTo(HaveOccurred())
				admin := cfg.Users["admin"]
				Expect(admin.PasswordHash).NotTo(BeEmpty())

				// Verify the hash is valid
				err = bcrypt.CompareHashAndPassword(
					[]byte(admin.PasswordHash),
					[]byte("admin-password"),
				)
				Expect(err).NotTo(HaveOccurred())
			})

			It("generates deterministic user IDs", func() {
				cfg, err := config.Load(configPath)

				Expect(err).NotTo(HaveOccurred())
				admin := cfg.Users["admin"]
				Expect(admin.ID).NotTo(BeEmpty())

				// Load again and verify same ID
				cfg2, err := config.Load(configPath)
				Expect(err).NotTo(HaveOccurred())
				admin2 := cfg2.Users["admin"]
				Expect(admin2.ID).To(Equal(admin.ID))
			})

			It("parses RSA private keys", func() {
				cfg, err := config.Load(configPath)

				Expect(err).NotTo(HaveOccurred())
				key, err := cfg.JWT.GetPrivateKey("key-1")
				Expect(err).NotTo(HaveOccurred())
				Expect(key).NotTo(BeNil())
				Expect(key.N.BitLen()).To(BeNumerically(">=", 2048))
			})
		})

		Context("with defaults", func() {
			BeforeEach(func() {
				minimalConfig := `
server:
  issuer: "https://uaa.example.com"

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

clients: {}
users: {}
`
				err := os.WriteFile(configPath, []byte(minimalConfig), 0644)
				Expect(err).NotTo(HaveOccurred())
			})

			It("uses default port 8443", func() {
				cfg, err := config.Load(configPath)

				Expect(err).NotTo(HaveOccurred())
				Expect(cfg.Server.Port).To(Equal(8443))
			})

			It("uses default access_token_validity 43200", func() {
				cfg, err := config.Load(configPath)

				Expect(err).NotTo(HaveOccurred())
				Expect(cfg.JWT.AccessTokenValidity).To(Equal(43200))
			})

			It("uses default refresh_token_validity 2592000", func() {
				cfg, err := config.Load(configPath)

				Expect(err).NotTo(HaveOccurred())
				Expect(cfg.JWT.RefreshTokenValidity).To(Equal(2592000))
			})
		})

		Context("with invalid configuration", func() {
			It("returns error for missing TLS certificate", func() {
				invalidConfig := `
server:
  issuer: "https://uaa.example.com"

tls:
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    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
    -----END RSA PRIVATE KEY-----

jwt:
  active_key_id: "key-1"
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
`
				err := os.WriteFile(configPath, []byte(invalidConfig), 0644)
				Expect(err).NotTo(HaveOccurred())

				_, err = config.Load(configPath)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("TLS certificate"))
			})

			It("returns error for invalid RSA key", func() {
				invalidConfig := `
server:
  issuer: "https://uaa.example.com"

tls:
  certificate: |
    -----BEGIN CERTIFICATE-----
    MIICljCCAX4CCQCKz8Vvdh5VuzANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
    -----END CERTIFICATE-----
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAq7BAxYCtgGH9F1h+OQFK
    -----END RSA PRIVATE KEY-----

jwt:
  active_key_id: "key-1"
  keys:
    key-1:
      signing_key: "not-a-valid-pem"
`
				err := os.WriteFile(configPath, []byte(invalidConfig), 0644)
				Expect(err).NotTo(HaveOccurred())

				_, err = config.Load(configPath)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("signing key"))
			})

			It("returns error for missing client secret", func() {
				invalidConfig := `
server:
  issuer: "https://uaa.example.com"

` + validTLSSection + `

` + validJWTSection + `

clients:
  test_client:
    authorized_grant_types:
      - client_credentials
`
				err := os.WriteFile(configPath, []byte(invalidConfig), 0644)
				Expect(err).NotTo(HaveOccurred())

				_, err = config.Load(configPath)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("secret"))
			})

			It("returns error for invalid active_key_id", func() {
				invalidConfig := `
server:
  issuer: "https://uaa.example.com"

` + validTLSSection + `

jwt:
  active_key_id: "nonexistent"
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
`
				err := os.WriteFile(configPath, []byte(invalidConfig), 0644)
				Expect(err).NotTo(HaveOccurred())

				_, err = config.Load(configPath)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("active_key_id"))
			})

			It("returns error for empty user password", func() {
				invalidConfig := `
server:
  issuer: "https://uaa.example.com"

` + validTLSSection + `

` + validJWTSection + `

users:
  admin:
    email: "admin@example.com"
    groups:
      - admin
`
				err := os.WriteFile(configPath, []byte(invalidConfig), 0644)
				Expect(err).NotTo(HaveOccurred())

				_, err = config.Load(configPath)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("password"))
			})
		})

		Context("with file errors", func() {
			It("returns error for nonexistent file", func() {
				_, err := config.Load("/nonexistent/path/config.yml")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to read"))
			})

			It("returns error for invalid YAML", func() {
				invalidYAML := `
server:
  port: 8443
  invalid yaml here: [
`
				err := os.WriteFile(configPath, []byte(invalidYAML), 0644)
				Expect(err).NotTo(HaveOccurred())

				_, err = config.Load(configPath)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("YAML"))
			})
		})
	})

	Describe("generateUserID", func() {
		It("generates same UUID for same username", func() {
			// We need to expose this or test through Load
			// For now, we test through the Load function
			validConfig := `
server:
  issuer: "https://uaa.example.com"
` + validTLSSection + `
` + validJWTSection + `
users:
  testuser:
    password: "password"
    email: "test@example.com"
    groups: [admin]
`
			err := os.WriteFile(configPath, []byte(validConfig), 0644)
			Expect(err).NotTo(HaveOccurred())

			cfg1, err := config.Load(configPath)
			Expect(err).NotTo(HaveOccurred())

			cfg2, err := config.Load(configPath)
			Expect(err).NotTo(HaveOccurred())

			Expect(cfg1.Users["testuser"].ID).To(Equal(cfg2.Users["testuser"].ID))
		})

		It("generates different UUID for different usernames", func() {
			validConfig := `
server:
  issuer: "https://uaa.example.com"
` + validTLSSection + `
` + validJWTSection + `
users:
  user1:
    password: "password"
    email: "user1@example.com"
    groups: [admin]
  user2:
    password: "password"
    email: "user2@example.com"
    groups: [admin]
`
			err := os.WriteFile(configPath, []byte(validConfig), 0644)
			Expect(err).NotTo(HaveOccurred())

			cfg, err := config.Load(configPath)
			Expect(err).NotTo(HaveOccurred())

			Expect(cfg.Users["user1"].ID).NotTo(Equal(cfg.Users["user2"].ID))
		})

		It("generates valid UUID v5 format", func() {
			validConfig := `
server:
  issuer: "https://uaa.example.com"
` + validTLSSection + `
` + validJWTSection + `
users:
  testuser:
    password: "password"
    email: "test@example.com"
    groups: [admin]
`
			err := os.WriteFile(configPath, []byte(validConfig), 0644)
			Expect(err).NotTo(HaveOccurred())

			cfg, err := config.Load(configPath)
			Expect(err).NotTo(HaveOccurred())

			// UUID format: 8-4-4-4-12
			Expect(cfg.Users["testuser"].ID).To(MatchRegexp(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`))
		})
	})
})
