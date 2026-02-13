# UAA-Lite

A lightweight OAuth2/OIDC authentication server designed as a minimal replacement for [Cloud Foundry UAA](https://github.com/cloudfoundry/uaa) in BOSH Director environments.

## Overview

UAA-Lite provides the essential OAuth2 functionality required by BOSH Director and its CLI clients, without the complexity of a full UAA deployment. It's implemented in Go and packaged as a BOSH release.

## Features

- **OAuth2 Grant Types**: `password`, `refresh_token`, `client_credentials`
- **JWT Tokens**: RS256-signed access tokens with configurable validity
- **Key Rotation**: Multiple signing keys with seamless rotation support
- **TLS**: HTTPS-only with TLS 1.2+ enforcement
- **BOSH Integration**: Native BOSH release with Monit process monitoring

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/token` | POST | Issue access/refresh tokens |
| `/oauth/check_token` | POST | Token introspection |
| `/token_key` | GET | Active public key (JWK + PEM) |
| `/token_keys` | GET | All public keys (JWKS + PEM) |
| `/info` | GET | Server metadata |
| `/healthz` | GET | Health check |

## Usage

### Deploy with BOSH

```yaml
releases:
  - name: uaa-lite
    version: latest

instance_groups:
  - name: bosh
    jobs:
      - name: uaa
        release: uaa-lite
        properties:
          uaa:
            port: 8443
            issuer: "https://((external_ip)):8443"
            tls:
              certificate: ((uaa_tls.certificate))
              private_key: ((uaa_tls.private_key))
            jwt:
              policy:
                active_key_id: "key-1"
                keys:
                  key-1:
                    signingKey: ((uaa_jwt_signing_key.private_key))
            clients:
              bosh_cli:
                secret: ((bosh_cli_secret))
                authorized_grant_types: [password, refresh_token]
                scope: [openid, bosh.admin]
                authorities: [uaa.none]
            users:
              admin:
                password: ((admin_password))
                email: admin@bosh
                groups: [bosh.admin, openid]
```

### Obtain a Token

```bash
curl -k -X POST https://localhost:8443/oauth/token \
  -u bosh_cli:client-secret \
  -d "grant_type=password&username=admin&password=admin-pass"
```

## Scope

UAA-Lite intentionally supports only the subset of UAA functionality needed for BOSH Director authentication:

**Supported:**
- Password, refresh token, and client credentials grants
- JWT access tokens with RS256 signing
- Static client and user configuration via BOSH properties
- Token introspection for resource servers

**Not Supported:**
- SAML/LDAP/external identity providers
- User management API
- Authorization code / implicit grants
- OpenID Connect userinfo endpoint
- Multi-zone deployments

## Documentation

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

## License

Apache License 2.0
