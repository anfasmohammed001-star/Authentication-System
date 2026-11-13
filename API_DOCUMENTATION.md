# API Documentation — Secure User Authentication System

Base URL (local development): `http://localhost:5000`

All API responses follow a consistent JSON envelope with a boolean `success` field. Passwords and `passwordHash` values are **never** logged or returned by any endpoint.

---

## Authentication Mechanisms

The API supports two compatible ways to authenticate protected requests:

1. **Primary (Browser Clients): `HttpOnly` Cookie (`auth_token`)**
   - Automatically set by `POST /api/auth/login` with `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` (enabled in production).
   - Sent automatically by browsers when requests include `credentials: 'include'` (or same-origin requests).
2. **Fallback (API / Mobile / CLI Clients): `Authorization: Bearer <jwt>` Header**
   - Send `Authorization: Bearer <token>` using the `token` returned in the `POST /api/auth/login` JSON response.

---

## Endpoints Summary

| Method | Path | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | No | Health and database connectivity check |
| `POST` | `/api/auth/register` | No | Validate, sanitize, hash password, and register user |
| `POST` | `/api/auth/login` | No | Verify credentials, enforce lockout, and issue JWT |
| `POST` | `/api/auth/logout` | Optional | Revoke active JWT server-side and clear cookie |
| `POST` | `/api/auth/forgot-password` | No | Request single-use cryptographically secure reset token |
| `POST` | `/api/auth/reset-password` | No | Reset password using valid token and invalidate sessions |
| `POST` | `/api/auth/change-password` | **Yes** | Change password with current password verification |
| `GET` | `/api/auth/me` | **Yes** | Retrieve authenticated user profile & session expiration |
| `GET` | `/api/dashboard` | **Yes** | Retrieve protected dashboard payload for authenticated user |
| `GET` | `/api/auth/admin/users` | **Yes (Admin)** | List registered users (RBAC enforced) |
| `GET` | `/api/auth/admin/stats` | **Yes (Admin)** | System security telemetry & configuration audit |

---

## 1. Register a New User

- **Method:** `POST`
- **URL:** `/api/auth/register`
- **Auth Required:** No (rate-limited)
- **Headers:** `Content-Type: application/json`

### Request Body Schema

| Field | Type | Required | Rules & Sanitization |
| :--- | :--- | :--- | :--- |
| `username` | `string` | Yes | Trimmed; control chars stripped; 3–30 chars matching `^[a-zA-Z0-9_-]{3,30}$`. Rejects `< > ' " \` \`. Case-insensitive uniqueness enforced. |
| `email` | `string` | Yes | Trimmed & lowercased; RFC-valid email (`<= 254` chars). Rejects HTML/control chars. Unique across all accounts. |
| `password` | `string` | Yes | 8 chars minimum, `<= 72` UTF-8 bytes; must include uppercase, lowercase, digit, and special character. |

```json
{
  "username": "alice_dev",
  "email": "alice@example.com",
  "password": "StrongPassword#2026"
}
```

### Success Response — `201 Created`

```json
{
  "success": true,
  "message": "User registered successfully.",
  "data": {
    "user": {
      "id": "6732f48e1a2b3c4d5e6f7a8b",
      "username": "alice_dev",
      "email": "alice@example.com",
      "createdAt": "2026-11-12T01:56:03.000Z"
    }
  }
}
```

### Error Responses

- **`400 Bad Request` (`VALIDATION_ERROR`)** — Missing fields, invalid email, disallowed username characters/XSS payload, weak password, or non-string NoSQL operator objects.

```json
{
  "success": false,
  "code": "VALIDATION_ERROR",
  "message": "Password must include at least one uppercase letter, one lowercase letter, one number, and one special character.",
  "errors": [
    {
      "field": "password",
      "message": "Password must include at least one uppercase letter, one lowercase letter, one number, and one special character."
    }
  ]
}
```

- **`409 Conflict` (`DUPLICATE_EMAIL` | `DUPLICATE_USERNAME`)** — Email or username already exists.

```json
{
  "success": false,
  "code": "DUPLICATE_EMAIL",
  "message": "An account with this email address already exists.",
  "errors": [
    {
      "field": "email",
      "message": "Email address is already registered."
    }
  ]
}
```

- **`429 Too Many Requests` (`RATE_LIMIT_EXCEEDED`)** — Brute-force rate limit exceeded.

---

## 2. Authenticate / Login

- **Method:** `POST`
- **URL:** `/api/auth/login`
- **Auth Required:** No (rate-limited)
- **Headers:** `Content-Type: application/json`

### Request Body Schema

Accepts either `identifier` (auto-detects email vs. username), `email`, or `username`, plus `password`:

```json
{
  "identifier": "alice@example.com",
  "password": "StrongPassword#2026"
}
```

*(Also accepts `{ "email": "alice@example.com", "password": "..." }` or `{ "username": "alice_dev", "password": "..." }`.)*

### Success Response — `200 OK`

Sets `Set-Cookie: auth_token=<jwt>; Path=/; HttpOnly; SameSite=Lax` (and `Secure` in production).

```json
{
  "success": true,
  "message": "Login successful.",
  "data": {
    "user": {
      "id": "6732f48e1a2b3c4d5e6f7a8b",
      "username": "alice_dev",
      "email": "alice@example.com",
      "createdAt": "2026-11-12T01:56:03.000Z"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": "1h"
  }
}
```

### Error Responses

- **`400 Bad Request` (`VALIDATION_ERROR`)** — Missing credentials or malformed/non-string input.
- **`401 Unauthorized` (`INVALID_CREDENTIALS`)** — Wrong password or unregistered email/username (identical message returned to prevent user enumeration).

```json
{
  "success": false,
  "code": "INVALID_CREDENTIALS",
  "message": "Invalid email/username or password."
}
```

- **`429 Too Many Requests` (`RATE_LIMIT_EXCEEDED`)** — Too many failed/rapid login attempts.

---

## 3. Get Current Authenticated User (Protected)

- **Method:** `GET`
- **URL:** `/api/auth/me`
- **Auth Required:** **Yes**
- **Headers:** `Cookie: auth_token=<jwt>` **OR** `Authorization: Bearer <jwt>`

### Success Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "user": {
      "id": "6732f48e1a2b3c4d5e6f7a8b",
      "username": "alice_dev",
      "email": "alice@example.com",
      "createdAt": "2026-11-12T01:56:03.000Z"
    },
    "session": {
      "expiresAt": "2026-11-12T02:56:03.000Z"
    }
  }
}
```

### Error Responses

- **`401 Unauthorized` (`MISSING_TOKEN`)** — No cookie or `Authorization: Bearer` header present.
- **`401 Unauthorized` (`TOKEN_EXPIRED`)** — JWT expiration timestamp (`exp`) has passed.
- **`401 Unauthorized` (`INVALID_TOKEN`)** — JWT signature invalid, tampered payload, or disallowed algorithm.
- **`401 Unauthorized` (`TOKEN_REVOKED`)** — JWT was invalidated via `POST /api/auth/logout`.
- **`401 Unauthorized` (`USER_NOT_FOUND`)** — Account associated with the `sub` claim no longer exists.

```json
{
  "success": false,
  "code": "MISSING_TOKEN",
  "message": "Authentication required. Please log in."
}
```

---

## 4. Get Protected Dashboard Data (Protected)

- **Method:** `GET`
- **URL:** `/api/dashboard`
- **Auth Required:** **Yes**
- **Headers:** `Cookie: auth_token=<jwt>` **OR** `Authorization: Bearer <jwt>`

### Success Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "user": {
      "id": "6732f48e1a2b3c4d5e6f7a8b",
      "username": "alice_dev",
      "email": "alice@example.com",
      "createdAt": "2026-11-12T01:56:03.000Z"
    },
    "session": {
      "tokenId": "9f6b1804-8b2a-43e1-92c0-78c2d5e7a41b",
      "issuedAt": "2026-11-12T01:56:03.000Z",
      "expiresAt": "2026-11-12T02:56:03.000Z"
    },
    "securityProfile": {
      "passwordHashing": "bcrypt (12 rounds)",
      "tokenMechanism": "JWT (HS256) via HttpOnly cookie with Bearer header fallback",
      "revocationEnabled": true
    }
  }
}
```

### Error Responses

Same `401 Unauthorized` responses as `GET /api/auth/me`.

---

## 5. Logout & Token Invalidation

- **Method:** `POST`
- **URL:** `/api/auth/logout`
- **Auth Required:** Optional (idempotent; revokes token if provided and always clears the `HttpOnly` cookie)
- **Headers:** `Cookie: auth_token=<jwt>` or `Authorization: Bearer <jwt>`

### Success Response — `200 OK`

Clears the `auth_token` cookie (`Set-Cookie: auth_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax`) and records the token's `jti` in the `RevokedToken` TTL collection so the token cannot be replayed.

```json
{
  "success": true,
  "message": "Logged out successfully."
}
```

---

## 6. Health Check & Global Error Codes

- **`GET /api/health`** → `200 OK` `{ "success": true, "status": "ok", "database": "connected", "timestamp": "..." }`
- **`400 INVALID_JSON`** → Malformed JSON request body
- **`403 CORS_FORBIDDEN`** → Disallowed cross-origin request
- **`404 NOT_FOUND`** → Unknown `/api/*` endpoint
- **`413 PAYLOAD_TOO_LARGE`** → Request body exceeds `16kb` limit
---

## 7. Password Recovery & Account Management

### A. Forgot Password — `POST /api/auth/forgot-password`
- **Auth Required:** No (rate-limited)
- **Body:** `{ "email": "alice@example.com" }`
- **Response `200 OK`:**
  ```json
  {
    "success": true,
    "message": "If that email address is registered, password reset instructions have been generated."
  }
  ```
  *(Mitigates user enumeration by returning identical 200 response whether email exists or not. In development/testing, returns `resetToken` for verification).*

### B. Reset Password — `POST /api/auth/reset-password`
- **Auth Required:** No (rate-limited)
- **Body:** `{ "token": "<64-hex-token>", "newPassword": "NewStrongPassword#2027" }`
- **Behavior:**
  - Validates token against SHA-256 hash in database with 15-minute TTL.
  - Re-hashes new password using bcrypt (>= 12 rounds).
  - Clears reset token immediately (single-use enforcement).
  - Updates `passwordChangedAt`, automatically invalidating all previously issued JWT sessions.

### C. Change Password — `POST /api/auth/change-password`
- **Auth Required:** Yes
- **Body:** `{ "currentPassword": "OldPassword#2026", "newPassword": "BrandNewPassword#2027" }`
- **Behavior:** Verifies `currentPassword` against stored hash, applies new bcrypt hash, clears cookie, and invalidates older sessions.

---

## 8. Role-Based Access Control (RBAC) & Administrative Endpoints

- **`GET /api/auth/admin/users`** — `200 OK` (Admin only)
  - Requires valid JWT from an account with `role: 'admin'`.
  - Non-admin authenticated accounts receive `403 Forbidden` (`FORBIDDEN`).
  - Unauthenticated requests receive `401 Unauthorized` (`MISSING_TOKEN`).
- **`GET /api/auth/admin/stats`** — `200 OK` (Admin only)
  - Returns server security telemetry and active configuration metrics.

---

## 9. Account Lockout Protection & Brute Force Defense

- Failed login attempts trigger an atomic counter on the user account.
- **5 consecutive failed attempts** lock the account for **15 minutes** (`423 Locked`, `ACCOUNT_LOCKED`).
- Successful authentication resets the failed counter to 0.
- Timing attack defenses ensure nonexistent user lookups execute a constant-time dummy bcrypt comparison.

