# Single Auth Service

A production-ready centralized authentication and identity service (IdP) in Go, implementing OAuth 2.1, OpenID Connect, and device-bound session management.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENTS                                        │
│         Web Apps │ Mobile Apps │ Backend Services │ Third-party Apps        │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AUTH SERVICE (This Project)                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   HTTP API  │  │  OAuth 2.1  │  │    OIDC     │  │  Device Management  │ │
│  │  (Gin)      │  │  Flows      │  │  Discovery  │  │  Multi-device SSO   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ JWT/RS256   │  │   PKCE      │  │  Key        │  │  Token Revocation   │ │
│  │ Signing     │  │  Required   │  │  Rotation   │  │  per Device         │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              ▼                                 ▼
┌─────────────────────────┐      ┌─────────────────────────┐
│      PostgreSQL         │      │         Redis           │
│  • Users                │      │  • Auth Codes (TTL)     │
│  • OAuth Clients        │      │  • Rate Limiting        │
│  • Refresh Tokens       │      │  • Session Cache        │
│  • Devices              │      │                         │
│  • Signing Keys         │      │                         │
└─────────────────────────┘      └─────────────────────────┘
```

## Features

### OAuth 2.1 Compliant
- **Authorization Code Flow + PKCE** (mandatory, not optional)
- **Client Credentials Flow** for service-to-service auth
- **Refresh Token Rotation** with automatic revocation
- **Token Revocation** endpoint (RFC 7009)

### OpenID Connect
- Discovery endpoint (`/.well-known/openid-configuration`)
- JWKS endpoint (`/jwks.json`)
- ID Token issuance
- Standard claims support

### Device-Bound Session Management
- **Server-generated device IDs** (cryptographically secure)
- **Per-device token binding** - tokens only work on their issued device
- **Granular session control**:
  - Logout single device
  - Logout all except current
  - Global logout
- **Token theft mitigation** - device mismatch triggers all-session revocation

### Security
- **Argon2id** password hashing (OWASP recommended parameters)
- **RS256** JWT signing with key rotation
- **PKCE required** for all authorization code flows
- **Refresh token rotation** with single-use enforcement
- **Rate limiting** on auth endpoints
- **CSRF protection** for web flows

## Quick Start

### Using Docker Compose

```bash
# Clone and start
git clone <repo>
cd single-auth-service
docker-compose up -d

# Service available at http://localhost:8080
```

### Manual Setup

```bash
# Prerequisites: Go 1.22+, PostgreSQL 16+, Redis 7+

# Install dependencies
make deps

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Run migrations
make migrate

# Build and run
make run
```

## API Reference

### Discovery & Keys

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OIDC discovery document |
| `/jwks.json` | GET | JSON Web Key Set |

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/register` | POST | Register new user |
| `/auth/login` | POST | Login and get device-bound tokens |
| `/auth/logout` | POST | Logout current device |

### OAuth 2.1

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/authorize` | GET | Authorization endpoint |
| `/token` | POST | Token endpoint (all grant types) |
| `/token/refresh` | POST | Refresh tokens |
| `/token/revoke` | POST | Revoke tokens |

### Device Management

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/devices` | GET | Required | List user's devices |
| `/logout/device/:id` | POST | Required | Logout specific device |
| `/logout/others` | POST | Required | Logout all except current |
| `/logout/all` | POST | Required | Global logout |

### Client Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/client` | POST | Create OAuth client |

## Token Flows

### Authorization Code Flow (Web/Mobile Apps)

```
┌──────────┐                              ┌──────────────┐                              ┌──────────┐
│  Client  │                              │ Auth Service │                              │   User   │
└────┬─────┘                              └──────┬───────┘                              └────┬─────┘
     │                                           │                                           │
     │ 1. Redirect to /authorize                 │                                           │
     │   ?response_type=code                     │                                           │
     │   &client_id=...                          │                                           │
     │   &redirect_uri=...                       │                                           │
     │   &code_challenge=... (PKCE)              │                                           │
     │   &code_challenge_method=S256             │                                           │
     │──────────────────────────────────────────>│                                           │
     │                                           │                                           │
     │                                           │ 2. Authenticate & Consent                 │
     │                                           │<─────────────────────────────────────────>│
     │                                           │                                           │
     │ 3. Redirect with code                     │                                           │
     │<──────────────────────────────────────────│                                           │
     │                                           │                                           │
     │ 4. POST /token                            │                                           │
     │   grant_type=authorization_code           │                                           │
     │   code=...                                │                                           │
     │   code_verifier=... (PKCE)                │                                           │
     │──────────────────────────────────────────>│                                           │
     │                                           │                                           │
     │ 5. Response:                              │                                           │
     │   access_token                            │                                           │
     │   refresh_token                           │                                           │
     │   device_id                               │                                           │
     │   id_token                                │                                           │
     │<──────────────────────────────────────────│                                           │
     │                                           │                                           │
```

### Device-Bound Token Usage

```
┌──────────┐                              ┌──────────────┐                              ┌──────────────┐
│  Client  │                              │ Auth Service │                              │   Resource   │
└────┬─────┘                              └──────┬───────┘                              └──────┬───────┘
     │                                           │                                             │
     │ API Request                               │                                             │
     │ Headers:                                  │                                             │
     │   Authorization: Bearer <access_token>    │                                             │
     │   X-Device-ID: <device_id>                │                                             │
     │────────────────────────────────────────────────────────────────────────────────────────>│
     │                                           │                                             │
     │                                           │ Validate:                                   │
     │                                           │ 1. JWT signature (via JWKS)                 │
     │                                           │ 2. Issuer & audience                        │
     │                                           │ 3. device_id in JWT == X-Device-ID header   │
     │                                           │<────────────────────────────────────────────│
     │                                           │                                             │
     │ Response                                  │                                             │
     │<───────────────────────────────────────────────────────────────────────────────────────│
     │                                           │                                             │
```

### Token Refresh (with Rotation)

```
┌──────────┐                              ┌──────────────┐
│  Client  │                              │ Auth Service │
└────┬─────┘                              └──────┬───────┘
     │                                           │
     │ POST /token                               │
     │   grant_type=refresh_token                │
     │   refresh_token=<old_token>               │
     │   client_id=...                           │
     │   device_id=... (REQUIRED!)               │
     │──────────────────────────────────────────>│
     │                                           │
     │                                           │ 1. Verify refresh token
     │                                           │ 2. Verify device binding
     │                                           │ 3. REVOKE old refresh token
     │                                           │ 4. Issue NEW refresh token
     │                                           │ 5. Issue NEW access token
     │                                           │
     │ Response:                                 │
     │   access_token (new)                      │
     │   refresh_token (new, rotated!)           │
     │<──────────────────────────────────────────│
     │                                           │
```

## JWT Structure

### Access Token Claims

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-uuid",
  "aud": ["client_id"],
  "exp": 1700000000,
  "iat": 1699999100,
  "nbf": 1699999100,
  "jti": "unique-token-id",
  "device_id": "device-uuid",
  "client_id": "client_id",
  "scope": "openid email",
  "typ": "access"
}
```

### ID Token Claims

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-uuid",
  "aud": "client_id",
  "exp": 1700003600,
  "iat": 1699999100,
  "auth_time": 1699999100,
  "nonce": "random-nonce",
  "email": "user@example.com",
  "email_verified": true
}
```

## Validating Tokens in Your Services

### Go Service

```go
package main

import (
    "crypto/rsa"
    "encoding/json"
    "net/http"

    "github.com/golang-jwt/jwt/v5"
)

// Fetch JWKS from auth service
func getPublicKey(kid string) (*rsa.PublicKey, error) {
    resp, _ := http.Get("https://auth.example.com/jwks.json")
    var jwks struct {
        Keys []struct {
            KID string `json:"kid"`
            N   string `json:"n"`
            E   string `json:"e"`
        } `json:"keys"`
    }
    json.NewDecoder(resp.Body).Decode(&jwks)

    // Find key by kid and convert to RSA public key
    // ... implementation
}

func validateToken(tokenString, deviceID string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        kid := token.Header["kid"].(string)
        return getPublicKey(kid)
    })

    claims := token.Claims.(*Claims)

    // CRITICAL: Verify device binding
    if claims.DeviceID != deviceID {
        return nil, errors.New("device mismatch")
    }

    return claims, nil
}
```

### PHP Service

```php
<?php
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

class TokenValidator {
    private $jwksUrl = 'https://auth.example.com/jwks.json';
    private $issuer = 'https://auth.example.com';

    public function validate(string $token, string $deviceId): array {
        // Fetch JWKS
        $jwks = json_decode(file_get_contents($this->jwksUrl), true);
        $keys = JWK::parseKeySet($jwks);

        // Decode and verify
        $decoded = JWT::decode($token, $keys);

        // Verify issuer
        if ($decoded->iss !== $this->issuer) {
            throw new Exception('Invalid issuer');
        }

        // CRITICAL: Verify device binding
        if ($decoded->device_id !== $deviceId) {
            throw new Exception('Device mismatch - potential token theft');
        }

        return (array) $decoded;
    }
}

// Usage in middleware
$validator = new TokenValidator();
$token = str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION']);
$deviceId = $_SERVER['HTTP_X_DEVICE_ID'] ?? '';

try {
    $claims = $validator->validate($token, $deviceId);
    // Token is valid, proceed with request
} catch (Exception $e) {
    http_response_code(401);
    exit('Unauthorized');
}
```

## Device Session Model

### Logout Scenarios

| Action | Effect |
|--------|--------|
| `POST /auth/logout` | Revokes current device only |
| `POST /logout/device/:id` | Revokes specific device |
| `POST /logout/others` | Revokes all devices except current |
| `POST /logout/all` | Global logout (all devices) |

### Device Mismatch Handling

If a token's `device_id` claim doesn't match the `X-Device-ID` header:
1. Request is **rejected immediately**
2. This indicates potential token theft
3. Consider revoking all user sessions

### Edge Cases

| Scenario | Behavior |
|----------|----------|
| Token used from different device | Rejected (device mismatch) |
| Refresh token stolen | Only works on original device |
| Multiple tabs same browser | Allowed (same device_id) |
| Device revoked, token valid | Refresh rejected, access expires naturally |

## Adding External OAuth Providers

The architecture supports OAuth provider federation. To add Google Sign-In:

### 1. Create Provider Interface

```go
// internal/domain/provider/provider.go
type OAuthProvider interface {
    GetAuthURL(state string) string
    Exchange(ctx context.Context, code string) (*ProviderToken, error)
    GetUserInfo(ctx context.Context, token *ProviderToken) (*ProviderUser, error)
}

type ProviderUser struct {
    ProviderUserID string
    Email          string
    EmailVerified  bool
    Name           string
}
```

### 2. Implement Google Provider

```go
// internal/infrastructure/providers/google.go
type GoogleProvider struct {
    clientID     string
    clientSecret string
    redirectURI  string
}

func (p *GoogleProvider) Exchange(ctx context.Context, code string) (*ProviderToken, error) {
    // Exchange code for token via Google OAuth
}

func (p *GoogleProvider) GetUserInfo(ctx context.Context, token *ProviderToken) (*ProviderUser, error) {
    // Fetch user info from Google
}
```

### 3. Add Callback Endpoint

```go
// GET /callback/google
func (h *AuthHandler) GoogleCallback(c *gin.Context) {
    code := c.Query("code")
    state := c.Query("state")

    // Validate state (CSRF protection)
    // Exchange code for provider token
    // Get user info from Google
    // Link or create user identity
    // Issue auth service tokens
}
```

### 4. Link Identity

```go
// Check if Google identity exists
identity, err := identityRepo.GetByProvider(ctx, "google", googleUserID)
if err != nil {
    // New identity - link to existing user or create new
    identity = user.NewUserIdentity(userID, "google", googleUserID)
    identityRepo.Create(ctx, identity)
}
```

## Key Rotation

Keys rotate automatically based on `JWT_KEY_ROTATION_INTERVAL`. The process:

1. New key generated and stored
2. New key set as active (old key deactivated)
3. JWKS cache invalidated
4. Old keys remain in JWKS for verification
5. Expired keys cleaned up after `JWT_KEY_VALIDITY_PERIOD`

**Zero-downtime rotation**: Old keys stay in JWKS, so tokens signed with them remain valid until expiry.

## Database Schema

```sql
-- Core tables
users                 -- User accounts
user_identities       -- External provider links (Google, Apple)
oauth_clients         -- Registered OAuth applications
user_devices          -- Device tracking for multi-device
refresh_tokens        -- Device-bound refresh tokens
signing_keys          -- RSA key pairs for JWT signing
```

See `migrations/` for complete schema.

## Environment Variables

See `.env.example` for all configuration options.

**Critical security settings:**
- `JWT_ISSUER`: Must be HTTPS in production
- `SECURE_COOKIES`: Must be `true` in production
- `DB_SSL_MODE`: Use `require` or `verify-full` in production

## Health Checks

| Endpoint | Description |
|----------|-------------|
| `/health` | Full health check (DB + Redis) |
| `/ready` | Readiness probe |
| `/live` | Liveness probe |
