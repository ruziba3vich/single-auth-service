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

## Getting Started: Step-by-Step

Before using the authentication APIs, you need to understand the flow:

```
1. Create OAuth Client  →  2. Register User  →  3. Login  →  4. Use Tokens
       ↓                         ↓                  ↓              ↓
   Get client_id            Get user_id      Get tokens      Access resources
```

### Why Do I Need a Client ID?

**The `client_id` is mandatory for login because this is an OAuth-based identity service, not a simple username/password system.**

Rationale:
- **Multi-application support**: Different apps (mobile, web, admin panel) can have different permissions
- **Token scoping**: Tokens are bound to specific clients, limiting blast radius if compromised
- **Audit trail**: Know which application issued which token
- **Revocation granularity**: Revoke all tokens for a specific app without affecting others

### Quick Start Example

```bash
# Step 1: Create an OAuth client (do this once per application)
curl -X POST http://localhost:8080/oauth/client \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Mobile App",
    "redirect_uris": ["myapp://callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "email"],
    "is_confidential": false
  }'
# Response: {"client_id": "abc123...", ...}

# Step 2: Register a user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass123!"}'

# Step 3: Login with the client_id from step 1
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "client_id": "abc123..."
  }'
# Response includes: access_token, refresh_token, device_id
```

---

## API Reference (Summary)

| Category | Endpoint | Method | Auth | Description |
|----------|----------|--------|------|-------------|
| **Discovery** | `/.well-known/openid-configuration` | GET | No | OIDC discovery document |
| | `/jwks.json` | GET | No | JSON Web Key Set for token verification |
| **Health** | `/health` | GET | No | Full health check (DB + Redis) |
| | `/ready` | GET | No | Kubernetes readiness probe |
| | `/live` | GET | No | Kubernetes liveness probe |
| **Auth** | `/auth/register` | POST | No | Register new user |
| | `/auth/login` | POST | No | Login and get device-bound tokens |
| | `/auth/logout` | POST | Device | Logout current device |
| **OAuth** | `/authorize` | GET | No | Start authorization code flow |
| | `/authorize` | POST | Yes | Submit user consent |
| | `/token` | POST | Varies | Exchange code/credentials for tokens |
| | `/token/refresh` | POST | No | Refresh access token |
| | `/token/revoke` | POST | No | Revoke a token |
| | `/oauth/client` | POST | No* | Register OAuth client |
| **Devices** | `/devices` | GET | Yes | List user's active devices |
| | `/logout/device/:id` | POST | Yes | Logout specific device |
| | `/logout/others` | POST | Yes | Logout all except current |
| | `/logout/all` | POST | Yes | Global logout (all devices) |

*In production, protect `/oauth/client` with admin authentication.

---

## Detailed API Documentation

### Health Endpoints

These endpoints support Kubernetes deployment and monitoring systems.

#### `GET /health` - Full Health Check

**Purpose**: Returns comprehensive health status including database and Redis connectivity.

**Why it exists**: Operations teams need to verify all dependencies are healthy, not just that the process is running.

**Response**:
```json
{
  "status": "healthy",
  "checks": {
    "database": "ok",
    "redis": "ok"
  }
}
```

**When to use**: Load balancer health checks, monitoring dashboards.

**When NOT to use**: High-frequency polling (use `/live` instead).

---

#### `GET /ready` - Readiness Probe

**Purpose**: Indicates whether the service can accept traffic.

**Why it exists**: Kubernetes needs to know when to route traffic to this pod. A pod might be alive but not yet ready (e.g., still warming up caches).

**Response**: `200 OK` if ready, `503 Service Unavailable` if not.

**When to use**: Kubernetes `readinessProbe` configuration.

---

#### `GET /live` - Liveness Probe

**Purpose**: Indicates whether the service process is alive and should not be restarted.

**Why it exists**: Kubernetes needs to detect deadlocked or frozen processes. This is a lightweight check that doesn't verify dependencies.

**Response**: `200 OK` if alive.

**When to use**: Kubernetes `livenessProbe` configuration.

**Design decision**: This intentionally does NOT check database/Redis. A service with a temporary database connection issue should not be killed and restarted—it should wait for the database to recover.

---

### Discovery & Keys

#### `GET /.well-known/openid-configuration` - OIDC Discovery

**Purpose**: Returns the OpenID Connect discovery document with all endpoint URLs and supported features.

**Why it exists**: OAuth/OIDC clients should auto-discover endpoints rather than hardcode them. This enables:
- Seamless endpoint changes without client updates
- Standard compliance (RFC 8414)
- Automatic client library configuration

**Response**:
```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "jwks_uri": "https://auth.example.com/jwks.json",
  "revocation_endpoint": "https://auth.example.com/token/revoke",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "code_challenge_methods_supported": ["S256"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"]
}
```

**When to use**: Initial client setup, OAuth library auto-configuration.

---

#### `GET /jwks.json` - JSON Web Key Set

**Purpose**: Returns public keys for verifying JWT signatures.

**Why it exists**: Resource servers (your APIs) need to verify tokens without calling the auth service for every request. JWKS enables:
- **Decentralized verification**: Any service can verify tokens independently
- **Key rotation**: Multiple keys can coexist during rotation
- **Performance**: No network call to auth service per request

**Response**:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-id-123",
      "use": "sig",
      "alg": "RS256",
      "n": "base64url-encoded-modulus...",
      "e": "AQAB"
    }
  ]
}
```

**Why multiple keys?** During key rotation, both old and new keys are present. Tokens signed with the old key remain valid until they expire.

**Caching**: Cache this response for 5-15 minutes. Re-fetch on verification failure (key might have rotated).

---

### Client Management

#### `POST /oauth/client` - Create OAuth Client

**Purpose**: Registers a new OAuth client application.

**Why it exists**: Before any user can login, you need a registered client. This is the foundational OAuth requirement—tokens are always issued to a specific client.

**When to use**:
- Setting up a new application (mobile app, web app, CLI tool)
- Creating service accounts for backend-to-backend communication

**Request**:
```json
{
  "name": "My Mobile App",
  "redirect_uris": ["myapp://callback", "https://myapp.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile", "email"],
  "is_confidential": false
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable application name |
| `redirect_uris` | Yes | Allowed callback URLs after authorization |
| `grant_types` | Yes | OAuth flows this client can use |
| `scopes` | No | Permissions this client can request |
| `is_confidential` | No | `true` for server apps, `false` for mobile/SPA |

**Grant Types Explained**:

| Grant Type | Use Case | Client Type |
|------------|----------|-------------|
| `authorization_code` | Web/mobile apps with user interaction | Public or Confidential |
| `refresh_token` | Long-lived sessions, token renewal | Any |
| `client_credentials` | Service-to-service (no user) | Confidential only |

**Confidential vs Public Clients**:

| Type | Can Keep Secret? | Examples | Auth Method |
|------|-----------------|----------|-------------|
| Confidential | Yes | Backend servers, secure environments | client_secret |
| Public | No | Mobile apps, SPAs, CLIs | PKCE only |

**Response**:
```json
{
  "id": "uuid",
  "client_id": "generated-client-id",
  "client_secret": "generated-secret-SAVE-THIS",
  "name": "My Mobile App",
  "redirect_uris": ["myapp://callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile", "email"],
  "created_at": "2024-01-15T10:30:00Z"
}
```

**⚠️ IMPORTANT**: `client_secret` is only returned once at creation. Store it securely. If lost, you must create a new client.

---

### Authentication Endpoints

#### `POST /auth/register` - User Registration

**Purpose**: Creates a new user account.

**Why it exists**: Users need accounts before they can authenticate. This is the entry point for new users.

**Request**:
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

| Field | Validation | Description |
|-------|------------|-------------|
| `email` | Required, valid email format | Unique identifier for the user |
| `password` | Required, min 8 characters | User's password (hashed with Argon2id) |

**Response** (`201 Created`):
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "email_verified": false,
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Error Cases**:

| Status | Error | Cause |
|--------|-------|-------|
| 400 | `invalid_request` | Missing/invalid email or password |
| 409 | `user_exists` | Email already registered |

**Security Notes**:
- Passwords are hashed using Argon2id (OWASP recommended)
- Email uniqueness is enforced at database level
- Rate limited to prevent enumeration attacks

---

#### `POST /auth/login` - User Login

**Purpose**: Authenticates a user and returns device-bound tokens.

**Why `client_id` is required**: See [Why Do I Need a Client ID?](#why-do-i-need-a-client-id)

**Why `device_id` is returned (not sent)**: The server generates device IDs cryptographically. This prevents:
- Device ID spoofing/guessing
- Clients claiming arbitrary device identities
- Token theft via device ID prediction

**Request**:
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "client_id": "your-client-id"
}
```

**Response** (`200 OK`):
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2g...",
  "device_id": "550e8400-e29b-41d4-a716-446655440000",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

| Field | Description |
|-------|-------------|
| `access_token` | Short-lived JWT for API access (15 min default) |
| `refresh_token` | Long-lived token for obtaining new access tokens |
| `device_id` | **Store this!** Required for all subsequent requests |
| `expires_in` | Access token lifetime in seconds |
| `id_token` | OIDC identity token with user claims |

**Critical: Store and Send Device ID**

After login, you MUST:
1. Store `device_id` securely (e.g., Keychain, SharedPreferences)
2. Send it as `X-Device-ID` header on all authenticated requests
3. Include it in token refresh requests

**Error Cases**:

| Status | Error | Cause |
|--------|-------|-------|
| 400 | `invalid_request` | Missing required fields |
| 401 | `invalid_credentials` | Wrong email or password |
| 400 | `invalid_client` | Unknown client_id |

---

#### `POST /auth/logout` - Logout Current Device

**Purpose**: Revokes tokens for the current device only.

**Why device-scoped logout?** Users expect "logout" to end their current session, not sign them out everywhere. For "sign out everywhere," use `/logout/all`.

**Headers Required**:
```
Authorization: Bearer <access_token>
X-Device-ID: <device_id>
```

**Response** (`200 OK`):
```json
{
  "message": "logged out successfully"
}
```

**What happens**:
1. Refresh token for this device is revoked
2. Access token remains valid until expiry (stateless JWT)
3. Other devices are unaffected

---

### OAuth 2.1 Endpoints

#### `GET /authorize` - Authorization Endpoint

**Purpose**: Initiates the OAuth authorization code flow.

**Why this exists**: Standard OAuth flow for web and mobile apps. The user is redirected here to authenticate and consent.

**Query Parameters**:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `response_type` | Yes | Must be `code` |
| `client_id` | Yes | Your registered client ID |
| `redirect_uri` | Yes | Must match registered URI exactly |
| `code_challenge` | Yes | PKCE challenge (S256 hash of verifier) |
| `code_challenge_method` | Yes | Must be `S256` |
| `scope` | No | Space-separated scopes (default: `openid`) |
| `state` | Recommended | CSRF protection, returned unchanged |
| `nonce` | For OIDC | Included in ID token to prevent replay |

**Example**:
```
GET /authorize?
  response_type=code&
  client_id=abc123&
  redirect_uri=https://myapp.com/callback&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256&
  scope=openid%20profile%20email&
  state=xyz789&
  nonce=random123
```

**Why PKCE is mandatory (not optional)**:
- OAuth 2.1 requires PKCE for ALL clients (not just public)
- Prevents authorization code interception attacks
- No exceptions—even confidential clients must use PKCE

**Flow**:
1. User is shown login/consent page
2. After authentication, redirected to `redirect_uri` with `?code=...&state=...`
3. Exchange code for tokens at `/token`

---

#### `POST /authorize` - Submit Consent

**Purpose**: Processes user consent after authentication.

**Why separate from GET?** GET displays the form, POST processes it. This follows POST-Redirect-GET pattern.

**Headers Required**:
```
Authorization: Bearer <access_token>
```

**Response**: Redirect to `redirect_uri` with authorization code.

---

#### `POST /token` - Token Endpoint

**Purpose**: Exchanges credentials for tokens. Supports multiple grant types.

**Content-Type**: `application/x-www-form-urlencoded`

##### Authorization Code Grant

**Use when**: User just completed `/authorize` flow.

**Request**:
```
grant_type=authorization_code&
code=<authorization_code>&
redirect_uri=https://myapp.com/callback&
client_id=abc123&
code_verifier=<original_pkce_verifier>
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | `authorization_code` |
| `code` | Yes | Code from authorize redirect |
| `redirect_uri` | Yes | Must match original request |
| `client_id` | Yes | Your client ID |
| `code_verifier` | Yes | PKCE verifier (plain text, hashed = challenge) |
| `client_secret` | Confidential | Required for confidential clients |

**Response**: Same as login response (access_token, refresh_token, device_id, id_token).

##### Client Credentials Grant

**Use when**: Service-to-service authentication (no user involved).

**Request**:
```
grant_type=client_credentials&
client_id=abc123&
client_secret=your-secret&
scope=some-scope
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "some-scope"
}
```

**Note**: No refresh token (just request new token when expired). No device_id (no user/device context).

##### Refresh Token Grant

**Use when**: Access token expired, need new one without re-authentication.

**Request**:
```
grant_type=refresh_token&
refresh_token=<your_refresh_token>&
client_id=abc123&
device_id=<your_device_id>
```

**Why device_id required?** Tokens are device-bound. This prevents stolen refresh tokens from being used on different devices.

**Response**: New access_token and NEW refresh_token (rotation).

---

#### `POST /token/refresh` - Explicit Refresh

**Purpose**: Alternative refresh endpoint with JSON body (more convenient for some clients).

**Why two refresh mechanisms?**
- `/token` with `grant_type=refresh_token`: Standard OAuth spec (form-encoded)
- `/token/refresh`: Convenience endpoint (JSON body, clearer intent)

**Request**:
```json
{
  "refresh_token": "your-refresh-token",
  "client_id": "your-client-id",
  "device_id": "your-device-id"
}
```

**Response**: Same as `/token` refresh grant.

**Token Rotation**: Every refresh issues a NEW refresh token and invalidates the old one. This limits the window for stolen token usage.

---

#### `POST /token/revoke` - Token Revocation

**Purpose**: Explicitly invalidates a token.

**Why it exists**: OAuth 2.0 Token Revocation (RFC 7009). Needed for:
- Logout implementations
- Security incident response
- User-initiated session termination

**Request**:
```json
{
  "token": "token-to-revoke",
  "token_type_hint": "refresh_token"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `token` | Yes | The token to revoke |
| `token_type_hint` | No | `access_token` or `refresh_token` |

**Response**: `200 OK` (always, even if token was already invalid—prevents token enumeration).

**What gets revoked?**
- Refresh token: Immediately unusable
- Access token: Revocation noted, but JWT may still validate until expiry (stateless)

---

### Device Management Endpoints

All device endpoints require authentication:
```
Authorization: Bearer <access_token>
X-Device-ID: <device_id>
```

#### `GET /devices` - List Active Devices

**Purpose**: Shows all devices where the user is logged in.

**Why it exists**: Users should see and manage their active sessions (like "Where You're Logged In" in Google/Facebook).

**Response**:
```json
{
  "devices": [
    {
      "device_id": "550e8400-e29b-41d4-a716-446655440000",
      "device_name": null,
      "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)...",
      "ip_address": "192.168.1.100",
      "last_used_at": "2024-01-15T10:30:00Z",
      "created_at": "2024-01-10T08:00:00Z",
      "is_current": true
    },
    {
      "device_id": "660e8400-e29b-41d4-a716-446655440001",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
      "ip_address": "10.0.0.50",
      "last_used_at": "2024-01-14T15:45:00Z",
      "created_at": "2024-01-05T12:00:00Z",
      "is_current": false
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `is_current` | `true` if this is the device making the request |
| `last_used_at` | Last time tokens were refreshed on this device |

---

#### `POST /logout/device/:device_id` - Logout Specific Device

**Purpose**: Revokes a specific device's session.

**Use case**: "I see an unknown device, remove it."

**Example**:
```bash
curl -X POST http://localhost:8080/logout/device/660e8400-e29b-41d4-a716-446655440001 \
  -H "Authorization: Bearer <token>" \
  -H "X-Device-ID: <current_device_id>"
```

**Response**: `200 OK`

**Security**: You can only revoke your own devices. Attempting to revoke another user's device returns 404.

---

#### `POST /logout/others` - Logout All Other Devices

**Purpose**: Signs out everywhere except the current device.

**Use case**: "I think my account was compromised, but I want to stay logged in on this phone."

**Response**:
```json
{
  "revoked_count": 3
}
```

---

#### `POST /logout/all` - Global Logout

**Purpose**: Signs out from ALL devices including the current one.

**Use case**: "Sign out everywhere" button, account compromise response.

**Response**:
```json
{
  "revoked_count": 4
}
```

**Note**: After this call, the current access token may still work until expiry (stateless JWT), but refresh will fail.

---

## Design Decisions & Rationale

### Why OAuth/OIDC Instead of Simple JWT Auth?

| Simple JWT Auth | OAuth/OIDC (This Service) |
|-----------------|---------------------------|
| One app, one token | Multiple apps, scoped tokens |
| No consent model | User consents to permissions |
| No standard discovery | Auto-discovery via .well-known |
| Custom token format | Standard, interoperable tokens |
| Tight coupling | Decoupled identity layer |

**Choose this service when**: Multiple applications, third-party integrations, enterprise requirements.

### Why Device-Bound Tokens?

Traditional tokens work anywhere—if stolen, attackers can use them from any location. Device binding adds a second factor:

```
Token alone: ❌ Rejected (no device context)
Token + correct device_id: ✅ Accepted
Token + wrong device_id: ❌ Rejected + security alert
```

### Why Server-Generated Device IDs?

Client-generated IDs are trivially spoofable:
```
# Attacker guesses or reuses device IDs
curl -H "X-Device-ID: victim-device-id" ...  # If client-generated, this works!
```

Server-generated IDs are:
- Cryptographically random (UUID v4)
- Bound to the session at creation
- Impossible to guess (2^122 possibilities)

### Why PKCE is Mandatory?

OAuth 2.0 PKCE was optional, leading to authorization code interception attacks. OAuth 2.1 makes it mandatory:

```
Without PKCE:
Attacker intercepts code → Exchanges for tokens → Account compromised

With PKCE:
Attacker intercepts code → Cannot exchange (no code_verifier) → Attack fails
```

### Why Refresh Token Rotation?

Single-use refresh tokens limit the damage window:

```
Standard refresh token:
Stolen token works forever until revoked

Rotating refresh token:
1. Token used → new token issued, old invalidated
2. Stolen token used → race condition detected
3. Both tokens invalidated → attacker and user locked out
4. User re-authenticates, attacker blocked
```

### What Are Redirect URIs (Callbacks)? Why Are They Needed?

**Common Confusion**: The `redirect_uris` in client registration are **NOT endpoints in this auth service**. They are URLs in **your client application** where the auth service will redirect users after authentication.

#### The OAuth Authorization Flow

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Your App       │         │  Auth Service   │         │  User's Browser │
│  (Client)       │         │  (This Project) │         │                 │
└────────┬────────┘         └────────┬────────┘         └────────┬────────┘
         │                           │                           │
         │ 1. User clicks "Login"    │                           │
         │───────────────────────────────────────────────────────>│
         │                           │                           │
         │                           │ 2. Redirect to /authorize │
         │                           │   with redirect_uri=      │
         │                           │   https://yourapp.com/    │
         │                           │   callback                │
         │                           │<──────────────────────────│
         │                           │                           │
         │                           │ 3. User logs in, consents │
         │                           │<─────────────────────────>│
         │                           │                           │
         │ 4. Redirect to YOUR app   │                           │
         │    https://yourapp.com/   │                           │
         │    callback?code=abc123   │                           │
         │<──────────────────────────│                           │
         │                           │                           │
         │ 5. Exchange code for      │                           │
         │    tokens at /token       │                           │
         │──────────────────────────>│                           │
         │                           │                           │
         │ 6. Return tokens          │                           │
         │<──────────────────────────│                           │
         │                           │                           │
```

#### Why Redirect URIs Must Be Pre-Registered

**Security Requirement**: The auth service ONLY redirects to URIs that were registered when the client was created. This prevents **authorization code interception attacks**:

```
Without URI validation (DANGEROUS):
1. Attacker tricks user: /authorize?redirect_uri=https://evil.com/steal
2. User authenticates with real auth service
3. Auth service redirects to evil.com with the code
4. Attacker exchanges code for tokens → Account compromised!

With URI validation (SAFE):
1. Attacker tries: /authorize?redirect_uri=https://evil.com/steal
2. Auth service checks: "Is evil.com in registered redirect_uris?"
3. Answer: NO → Request rejected with "invalid_redirect_uri" error
4. Attack prevented!
```

#### Redirect URI Examples by Platform

| Platform | Example Redirect URI | Notes |
|----------|---------------------|-------|
| Web App | `https://myapp.com/auth/callback` | Must be HTTPS in production |
| Mobile (iOS) | `myapp://callback` | Custom URL scheme |
| Mobile (Android) | `myapp://callback` or `https://myapp.com/.well-known/assetlinks.json` | App Links preferred |
| Desktop App | `http://localhost:8080/callback` | Localhost allowed for native apps |
| SPA | `https://spa.myapp.com/auth/complete` | Same-origin recommended |
| CLI Tool | `http://127.0.0.1:9999/callback` | Ephemeral port on localhost |

#### What Your Callback Endpoint Should Do

Your application's callback endpoint (e.g., `https://yourapp.com/callback`) must:

```
1. Receive the authorization code from query params
   GET /callback?code=abc123&state=xyz789

2. Verify the state matches what you sent (CSRF protection)

3. Exchange the code for tokens:
   POST /token
   grant_type=authorization_code
   code=abc123
   redirect_uri=https://yourapp.com/callback  ← Must match exactly!
   client_id=your-client-id
   code_verifier=your-pkce-verifier

4. Store the tokens securely

5. Redirect user to your app's main page
```

**Example callback handler (Node.js/Express)**:
```javascript
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  // Verify state matches session
  if (state !== req.session.oauth_state) {
    return res.status(400).send('Invalid state - possible CSRF attack');
  }

  // Exchange code for tokens
  const response = await fetch('https://auth.example.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: 'https://yourapp.com/callback',
      client_id: process.env.CLIENT_ID,
      code_verifier: req.session.code_verifier
    })
  });

  const tokens = await response.json();

  // Store tokens securely
  req.session.access_token = tokens.access_token;
  req.session.refresh_token = tokens.refresh_token;
  req.session.device_id = tokens.device_id;  // Important!

  res.redirect('/dashboard');
});
```

#### When You DON'T Need Redirect URIs

If you're using the **direct login flow** (`POST /auth/login`), you don't need callbacks:

```bash
# Direct login - no redirects, no callbacks needed
curl -X POST https://auth.example.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "pass", "client_id": "abc"}'

# Response contains tokens directly - no redirect
{"access_token": "...", "refresh_token": "...", "device_id": "..."}
```

**Use direct login when**:
- Mobile apps with native login UI
- CLI tools
- Server-to-server (client credentials)
- First-party apps where you control the login form

**Use OAuth authorize flow (with callbacks) when**:
- Third-party apps accessing your users' data
- "Login with YourService" buttons on other sites
- Web apps following OAuth best practices
- You want to support SSO across multiple apps

---

## Error Response Format

All errors follow a consistent format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable explanation"
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Malformed request, missing parameters |
| `invalid_client` | 400/401 | Unknown client_id or wrong secret |
| `invalid_grant` | 400 | Invalid/expired code or refresh token |
| `invalid_credentials` | 401 | Wrong email or password |
| `unauthorized` | 401 | Missing or invalid access token |
| `access_denied` | 403 | User denied consent or lacks permission |
| `invalid_token` | 401 | Token expired, revoked, or malformed |
| `device_mismatch` | 401 | X-Device-ID doesn't match token's device |
| `user_exists` | 409 | Email already registered |
| `server_error` | 500 | Internal server error |

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
