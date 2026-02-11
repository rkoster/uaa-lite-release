# UAA-Lite Architecture

UAA-Lite is a lightweight implementation of the Cloud Foundry UAA (User Account and Authentication) service, designed as a drop-in replacement for the full UAA in the context of the BOSH Director. It eliminates the heavy Java dependencies while maintaining compatibility with BOSH Director and config-server authentication flows.

## Table of Contents

- [Overview](#overview)
- [Design Principles](#design-principles)
- [System Architecture](#system-architecture)
- [Component Details](#component-details)
- [API Endpoints](#api-endpoints)
- [Authentication Flows](#authentication-flows)
- [Token Format](#token-format)
- [Configuration](#configuration)
- [BOSH Release Structure](#bosh-release-structure)
- [Security Considerations](#security-considerations)

---

## Overview

### Goals

1. **Minimal Footprint**: Single Go binary with no external database dependencies
2. **BOSH Director Compatibility**: Support the OAuth2 flows required by BOSH CLI and Director
3. **Config-Server Compatibility**: Issue JWT tokens that config-server can validate
4. **Operational Simplicity**: Static configuration via BOSH properties, no runtime state persistence

### Non-Goals

- Full UAA API compatibility (SCIM, SAML, LDAP, zones, etc.)
- Persistent storage of users, clients, or tokens
- Browser-based login flows (authorization code grant)
- Multi-tenancy (identity zones)

### Supported OAuth2 Grant Types

| Grant Type | Use Case |
|------------|----------|
| `client_credentials` | Service-to-service authentication (e.g., Director to config-server) |
| `password` | User authentication via BOSH CLI |
| `refresh_token` | Token refresh for long-running CLI sessions |

---

## Design Principles

### Stateless Access Tokens

Access tokens are self-contained JWTs signed with RSA keys. Any service with the public key can validate tokens without calling back to UAA-Lite. This matches how config-server validates tokens.

### Stateful Refresh Tokens

Refresh tokens are opaque strings stored in-memory. This provides:
- Ability to revoke refresh tokens (by restarting the service)
- No need for persistent storage
- Automatic cleanup on service restart

### Configuration-Driven

All users and clients are defined in the BOSH deployment manifest. There is no runtime API for creating or modifying users/clients. This simplifies operations and eliminates the need for a database.

### Secure by Default

- TLS termination built-in
- Passwords hashed with bcrypt on startup
- RSA-signed JWTs (RS256)
- No sensitive data in access tokens beyond what's necessary

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              BOSH Environment                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────────────────┐   │
│  │              │     │              │     │                          │   │
│  │  BOSH CLI    │────▶│  UAA-Lite    │◀────│  BOSH Director           │   │
│  │              │     │              │     │                          │   │
│  └──────────────┘     └──────────────┘     └──────────────────────────┘   │
│         │                    │                         │                   │
│         │                    │                         │                   │
│         │              ┌─────┴─────┐                   │                   │
│         │              │           │                   │                   │
│         │              ▼           │                   ▼                   │
│         │       ┌────────────┐     │          ┌──────────────┐            │
│         │       │ In-Memory  │     │          │              │            │
│         │       │  Refresh   │     │          │ Config-Server│            │
│         │       │   Store    │     │          │              │            │
│         │       └────────────┘     │          └──────────────┘            │
│         │                          │                   │                   │
│         │                          │                   │                   │
│         └──────────────────────────┼───────────────────┘                   │
│                                    │                                       │
│                             Validates JWTs                                 │
│                            using public key                                │
│                          fetched from /token_keys                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Request Flow

1. **BOSH CLI → UAA-Lite**: User authenticates with username/password (password grant)
2. **UAA-Lite**: Validates credentials, issues JWT access token + opaque refresh token
3. **BOSH CLI → BOSH Director**: Sends access token in Authorization header
4. **BOSH Director**: Validates JWT signature using public key from `/token_keys`
5. **BOSH Director → Config-Server**: Uses client_credentials grant for its own token
6. **Config-Server**: Validates JWT using pre-configured public key

---

## Component Details

### Project Structure

```
src/uaa-lite/
├── cmd/
│   └── uaa-lite/
│       └── main.go                    # Entry point, TLS server setup
│
├── internal/
│   ├── config/
│   │   ├── config.go                  # Configuration struct definitions
│   │   └── loader.go                  # YAML parsing, password hashing
│   │
│   ├── auth/
│   │   ├── jwt.go                     # JWT creation and validation
│   │   ├── claims.go                  # Token claims structures
│   │   ├── client_credentials.go      # client_credentials grant handler
│   │   ├── password_grant.go          # password grant handler
│   │   ├── refresh_grant.go           # refresh_token grant handler
│   │   └── refresh_store.go           # In-memory refresh token storage
│   │
│   ├── handlers/
│   │   ├── handlers.go                # HTTP router setup
│   │   ├── token.go                   # POST /oauth/token
│   │   ├── token_key.go               # GET /token_key, /token_keys
│   │   ├── check_token.go             # POST /check_token
│   │   ├── info.go                    # GET /info
│   │   └── health.go                  # GET /healthz
│   │
│   └── middleware/
│       └── basic_auth.go              # HTTP Basic Authentication
│
├── go.mod
└── go.sum
```

### Internal Components

#### Config Loader

Responsible for:
- Parsing YAML configuration file
- Loading RSA keys from PEM format
- Hashing plaintext passwords with bcrypt
- Validating configuration completeness

#### JWT Manager

Handles all JWT operations:
- Token creation with configurable claims
- RSA signature generation (RS256)
- Token validation and parsing
- Key ID (kid) management for rotation

#### Refresh Token Store

Thread-safe in-memory storage:
- Maps opaque tokens to metadata (user, client, scope, expiry)
- Background cleanup of expired tokens
- Token rotation on refresh (old token invalidated)

#### HTTP Handlers

Standard HTTP handlers using gorilla/mux:
- Request parsing and validation
- OAuth2 error response formatting
- Content-type negotiation

---

## API Endpoints

### Token Endpoint

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)
```

#### Client Credentials Grant

```
grant_type=client_credentials
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600,
  "scope": "bosh.admin config_server.admin"
}
```

#### Password Grant

```
grant_type=password&username=admin&password=secret&scope=openid+bosh.admin
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 600,
  "refresh_token": "r-abc123def456...",
  "scope": "openid bosh.admin"
}
```

#### Refresh Token Grant

```
grant_type=refresh_token&refresh_token=r-abc123def456...
```

Response: Same as password grant (with new tokens)

### Token Key Endpoints

```
GET /token_key
```

Returns the active signing key in JWK format:
```json
{
  "kty": "RSA",
  "alg": "RS256",
  "use": "sig",
  "kid": "key-1",
  "n": "0vx7agoebG...",
  "e": "AQAB",
  "value": "-----BEGIN PUBLIC KEY-----\n..."
}
```

```
GET /token_keys
```

Returns all signing keys (for rotation support):
```json
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "key-1",
      "n": "0vx7agoebG...",
      "e": "AQAB",
      "value": "-----BEGIN PUBLIC KEY-----\n..."
    }
  ]
}
```

### Token Introspection

```
POST /check_token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=eyJhbGciOiJSUzI1NiIs...
```

Response:
```json
{
  "jti": "8f7e6d5c-4b3a-2f1e-0d9c-8b7a6f5e4d3c",
  "sub": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "scope": ["openid", "bosh.admin"],
  "client_id": "bosh_cli",
  "user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "user_name": "admin",
  "email": "admin@example.com",
  "exp": 1738310400,
  "iat": 1738306800
}
```

### Info Endpoint

```
GET /info
```

Response:
```json
{
  "app": {
    "version": "1.0.0"
  },
  "links": {
    "uaa": "https://uaa.example.com:8443",
    "login": "https://uaa.example.com:8443"
  },
  "zone_name": "uaa",
  "entityID": "uaa.example.com",
  "prompts": {
    "username": ["text", "Username"],
    "password": ["password", "Password"]
  }
}
```

### Health Endpoint

```
GET /healthz
```

Response:
```json
{
  "status": "ok"
}
```

---

## Authentication Flows

### Flow 1: BOSH CLI Login (Password Grant)

```
┌──────────┐                  ┌──────────┐                  ┌──────────┐
│ BOSH CLI │                  │ UAA-Lite │                  │  Config  │
└────┬─────┘                  └────┬─────┘                  └────┬─────┘
     │                             │                              │
     │  POST /oauth/token          │                              │
     │  grant_type=password        │                              │
     │  username=admin             │                              │
     │  password=secret            │                              │
     │  (Basic Auth: bosh_cli)     │                              │
     │ ───────────────────────────▶│                              │
     │                             │                              │
     │                             │  Validate client credentials │
     │                             │  Validate user password      │
     │                             │  Calculate scope intersection│
     │                             │  Generate JWT access token   │
     │                             │  Generate refresh token      │
     │                             │  Store refresh token         │
     │                             │                              │
     │  {                          │                              │
     │    access_token: "...",     │                              │
     │    refresh_token: "...",    │                              │
     │    expires_in: 600          │                              │
     │  }                          │                              │
     │ ◀───────────────────────────│                              │
     │                             │                              │
```

### Flow 2: BOSH Director Token Validation

```
┌──────────┐                  ┌──────────┐                  ┌──────────┐
│ BOSH CLI │                  │ Director │                  │ UAA-Lite │
└────┬─────┘                  └────┬─────┘                  └────┬─────┘
     │                             │                              │
     │  API Request                │                              │
     │  Authorization: Bearer JWT  │                              │
     │ ───────────────────────────▶│                              │
     │                             │                              │
     │                             │  GET /token_keys             │
     │                             │  (cached)                    │
     │                             │ ────────────────────────────▶│
     │                             │                              │
     │                             │  { keys: [...] }             │
     │                             │ ◀────────────────────────────│
     │                             │                              │
     │                             │  Validate JWT signature      │
     │                             │  Check expiration            │
     │                             │  Check required scopes       │
     │                             │                              │
     │  API Response               │                              │
     │ ◀───────────────────────────│                              │
     │                             │                              │
```

### Flow 3: Director to Config-Server (Client Credentials)

```
┌──────────┐                  ┌──────────┐                  ┌──────────────┐
│ Director │                  │ UAA-Lite │                  │ Config-Server│
└────┬─────┘                  └────┬─────┘                  └──────┬───────┘
     │                             │                               │
     │  POST /oauth/token          │                               │
     │  grant_type=client_creds    │                               │
     │  (Basic Auth: director)     │                               │
     │ ───────────────────────────▶│                               │
     │                             │                               │
     │  { access_token: "..." }    │                               │
     │ ◀───────────────────────────│                               │
     │                             │                               │
     │  GET /v1/data/...           │                               │
     │  Authorization: Bearer JWT  │                               │
     │ ───────────────────────────────────────────────────────────▶│
     │                             │                               │
     │                             │   Validate JWT with           │
     │                             │   pre-configured public key   │
     │                             │   Check scope: config_server.admin
     │                             │                               │
     │  { value: "..." }           │                               │
     │ ◀───────────────────────────────────────────────────────────│
     │                             │                               │
```

---

## Token Format

### JWT Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-1"
}
```

- `alg`: Always RS256 (RSA with SHA-256)
- `typ`: Always JWT
- `kid`: Key ID, matches the active signing key

### JWT Claims (Password Grant)

```json
{
  "jti": "8f7e6d5c-4b3a-2f1e-0d9c-8b7a6f5e4d3c",
  "iss": "https://uaa.service.cf.internal:8443/oauth/token",
  "sub": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "aud": ["bosh", "openid"],
  "client_id": "bosh_cli",
  "user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "user_name": "admin",
  "email": "admin@example.com",
  "scope": ["openid", "bosh.admin"],
  "grant_type": "password",
  "iat": 1738306800,
  "exp": 1738310400
}
```

### JWT Claims (Client Credentials Grant)

```json
{
  "jti": "9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d",
  "iss": "https://uaa.service.cf.internal:8443/oauth/token",
  "sub": "director",
  "aud": ["bosh", "config_server"],
  "client_id": "director",
  "scope": ["bosh.admin", "config_server.admin"],
  "grant_type": "client_credentials",
  "iat": 1738306800,
  "exp": 1738310400
}
```

### Claim Descriptions

| Claim | Description |
|-------|-------------|
| `jti` | Unique token identifier (UUID) |
| `iss` | Issuer URL (UAA-Lite endpoint) |
| `sub` | Subject (user_id for password grant, client_id for client_credentials) |
| `aud` | Audience (automatically derived from scope prefixes, e.g., `bosh.admin` → `bosh`) |
| `client_id` | OAuth client that requested the token |
| `user_id` | User identifier (password grant only) |
| `user_name` | Username (password grant only) |
| `email` | User email (password grant only) |
| `scope` | Granted scopes (array of strings) |
| `grant_type` | OAuth grant type used |
| `iat` | Issued at (Unix timestamp) |
| `exp` | Expiration (Unix timestamp) |

### User ID Generation

User IDs are deterministically generated from usernames using UUID v5 (RFC 4122) to ensure stability across restarts. This uses a namespace-based UUID generation with SHA-1 hashing:

```go
import "github.com/google/uuid"

// UAA-Lite namespace UUID (generated once, constant)
var uaaLiteNamespace = uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

// Generate deterministic user ID from username
userID := uuid.NewSHA1(uaaLiteNamespace, []byte(username))
```

This produces the same UUID for the same username every time, without requiring persistent storage. The `github.com/google/uuid` library provides the standard UUID v5 implementation.

### Issuer URL

The `iss` claim in JWT tokens is populated from the `uaa.issuer` configuration property. This should be set to the externally-accessible URL of the UAA-Lite instance:

```yaml
server:
  issuer: "https://uaa.service.cf.internal:8443"
```

The issuer URL is used in:
- JWT `iss` claim
- OIDC discovery document (`/.well-known/openid-configuration`)
- `/info` endpoint links

### Audience Derivation

The `aud` (audience) claim is automatically derived from the granted scopes by extracting the prefix before the first dot:

```go
func deriveAudience(scopes []string) []string {
    audiences := make(map[string]bool)
    for _, scope := range scopes {
        if idx := strings.Index(scope, "."); idx > 0 {
            audiences[scope[:idx]] = true
        } else {
            audiences[scope] = true
        }
    }
    return mapKeys(audiences)
}
```

Examples:
| Scopes | Derived Audience |
|--------|------------------|
| `["bosh.admin", "bosh.read"]` | `["bosh"]` |
| `["config_server.admin"]` | `["config_server"]` |
| `["openid", "bosh.admin"]` | `["openid", "bosh"]` |
| `["bosh.admin", "config_server.admin", "openid"]` | `["bosh", "config_server", "openid"]` |

---

## Configuration

### YAML Configuration File

```yaml
# Server configuration
server:
  port: 8443
  issuer: "https://uaa.service.cf.internal:8443"

# TLS configuration  
tls:
  certificate: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----

# JWT signing configuration
jwt:
  active_key_id: "key-1"
  keys:
    key-1:
      signing_key: |
        -----BEGIN RSA PRIVATE KEY-----
        ...
        -----END RSA PRIVATE KEY-----
  access_token_validity: 43200    # 12 hours
  refresh_token_validity: 2592000  # 30 days

# OAuth clients
clients:
  bosh_cli:
    secret: "bosh-cli-secret"
    authorized_grant_types:
      - password
      - refresh_token
    scope:
      - openid
      - bosh.admin
      - bosh.read
    authorities:
      - uaa.none
    access_token_validity: 600
    refresh_token_validity: 86400

  director:
    secret: "director-secret"
    authorized_grant_types:
      - client_credentials
    authorities:
      - bosh.admin
      - uaa.resource
      - config_server.admin
    access_token_validity: 3600

# Users (passwords in plaintext, hashed on startup)
users:
  admin:
    password: "admin-password"
    email: "admin@example.com"
    groups:
      - bosh.admin
      - scim.read
      - openid

  operator:
    password: "operator-password"
    email: "operator@example.com"
    groups:
      - bosh.read
      - openid
```

### Configuration Validation

On startup, UAA-Lite validates:

1. **TLS**: Certificate and private key are valid and match
2. **JWT Keys**: At least one signing key exists, active_key_id points to valid key
3. **Clients**: Each client has a secret and at least one grant type
4. **Users**: Each user has a password and email
5. **Grant Types**: Clients using `password` grant have `scope` defined

### Scope Resolution

#### Password Grant

The granted scope is the intersection of:
1. Scopes requested in the token request (optional)
2. User's groups
3. Client's allowed scopes

```
If request.scope is empty:
    granted = user.groups ∩ client.scope
Else:
    granted = request.scope ∩ user.groups ∩ client.scope
```

#### Client Credentials Grant

The granted scope is the client's `authorities`:

```
granted = client.authorities
```

---

## BOSH Release Structure

```
.
├── jobs/
│   └── uaa/
│       ├── spec                       # Job specification
│       ├── monit                      # Process monitoring
│       └── templates/
│           ├── config.yml.erb         # Configuration file
│           ├── tls_cert.pem.erb       # TLS certificate
│           ├── tls_key.pem.erb        # TLS private key
│           └── ctl.erb                # Control script
│
├── packages/
│   ├── uaa/
│   │   ├── spec                       # Package dependencies
│   │   └── packaging                  # Build script
│   │
│   └── golang-1.26-linux/
│       └── spec.lock                  # Go compiler
│
└── src/
    └── uaa-lite/                      # Go source code
        ├── cmd/
        ├── internal/
        ├── go.mod
        └── go.sum
```

### Job Specification (jobs/uaa/spec)

```yaml
name: uaa

templates:
  ctl.erb: bin/ctl
  config.yml.erb: config/config.yml
  tls_cert.pem.erb: config/tls_cert.pem
  tls_key.pem.erb: config/tls_key.pem

packages:
  - uaa

properties:
  uaa.port:
    description: "HTTPS port"
    default: 8443

  uaa.issuer:
    description: "Token issuer URL"
    default: ""

  uaa.tls.certificate:
    description: "TLS certificate (PEM)"

  uaa.tls.private_key:
    description: "TLS private key (PEM)"

  uaa.jwt.policy.active_key_id:
    description: "Active signing key ID"
    default: "key-1"

  uaa.jwt.policy.keys:
    description: "Signing keys (map of key_id to key config)"

  uaa.jwt.policy.access_token_validity:
    description: "Default access token validity (seconds)"
    default: 43200

  uaa.jwt.policy.refresh_token_validity:
    description: "Default refresh token validity (seconds)"
    default: 2592000

  uaa.clients:
    description: "OAuth client configurations"
    default: {}

  uaa.users:
    description: "User configurations"
    default: {}
```

### Monit Configuration

```
check process uaa
  with pidfile /var/vcap/sys/run/uaa/uaa.pid
  start program "/var/vcap/jobs/uaa/bin/ctl start"
  stop program "/var/vcap/jobs/uaa/bin/ctl stop"
  group vcap
```

---

## Security Considerations

### Password Storage

- Passwords are provided in plaintext in BOSH manifests (stored in CredHub/Vault)
- UAA-Lite hashes passwords with bcrypt (cost=10) on startup
- Plaintext passwords are never logged or stored

### Token Security

- Access tokens are signed with RSA (RS256), 2048-bit minimum key size
- Refresh tokens are cryptographically random (32 bytes, base64url encoded)
- Token JTIs are UUIDs to prevent replay attacks
- Short access token lifetimes reduce exposure window

### TLS

- TLS 1.2+ required
- Server terminates TLS directly (no proxy needed)
- Certificate and key provided via BOSH properties

### In-Memory State

- Refresh tokens stored in-memory only
- Server restart invalidates all refresh tokens
- No persistent state = no database attack surface

### Client Authentication

- All token endpoints require HTTP Basic authentication
- Client secrets compared using constant-time comparison
- Failed authentication attempts are logged

### Scope Restrictions

- Users can only get scopes they're entitled to (group membership)
- Clients can only issue scopes within their allowed scope list
- Client credentials grant uses `authorities`, not `scope`

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/golang-jwt/jwt/v5` | v5.2.x | JWT creation and validation |
| `github.com/google/uuid` | v1.6.x | Deterministic UUID generation (v5) for user IDs |
| `github.com/gorilla/mux` | v1.8.x | HTTP routing |
| `golang.org/x/crypto` | latest | bcrypt password hashing |
| `gopkg.in/yaml.v3` | v3.0.x | Configuration parsing |

---

## Error Handling

### OAuth2 Error Responses

All errors follow RFC 6749 format:

```json
{
  "error": "invalid_grant",
  "error_description": "Bad credentials"
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Malformed request |
| `invalid_client` | 401 | Bad client credentials |
| `invalid_grant` | 400 | Bad user credentials or invalid refresh token |
| `unauthorized_client` | 400 | Client not authorized for grant type |
| `unsupported_grant_type` | 400 | Grant type not supported |
| `invalid_scope` | 400 | Requested scope exceeds allowed scope |
| `invalid_token` | 401 | Token validation failed |

---

## Monitoring and Operations

### Health Check

```
GET /healthz
```

Returns 200 OK when the service is healthy.

### Logging

Structured JSON logging to stdout:

```json
{
  "level": "info",
  "time": "2024-01-31T12:00:00Z",
  "msg": "token issued",
  "client_id": "bosh_cli",
  "grant_type": "password",
  "user": "admin",
  "scope": "openid bosh.admin"
}
```

### Metrics (Future)

Prometheus-compatible metrics endpoint at `/metrics`:

- `uaa_token_requests_total{grant_type, status}`
- `uaa_token_request_duration_seconds{grant_type}`
- `uaa_refresh_tokens_active`

---

## Limitations

1. **No Persistence**: All state (refresh tokens) is lost on restart
2. **No SCIM**: Users cannot be created/modified via API
3. **No SAML/LDAP**: Only internal user database supported
4. **No Authorization Code**: Browser-based flows not supported
5. **Single Zone**: No multi-tenancy support
6. **No Token Revocation API**: Tokens can only be revoked by restart

---

## Future Enhancements

1. **Optional Persistence**: Redis backend for refresh tokens
2. **Key Rotation**: Automated key rotation with overlap period
3. **Rate Limiting**: Protect against brute force attacks
4. **Metrics**: Prometheus endpoint for monitoring
5. **Audit Logging**: Detailed authentication event logging
