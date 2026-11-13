# Secure User Authentication System

A production-structured, security-hardened full-stack **User Authentication System** built with **Node.js, Express, MongoDB (Mongoose), bcrypt, and JWT (`HttpOnly` cookies + `Bearer` header fallback)**, paired with a responsive modern frontend styled in **3D Claymorphism and Frosted Glassmorphism**.

**Target GitHub Repository:** [https://github.com/anfasmohammed001-star/Authentication-System.git](https://github.com/anfasmohammed001-star/Authentication-System.git)

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Key Features](#key-features)
3. [Technology Stack](#technology-stack)
4. [Repository & Project Structure](#repository--project-structure)
5. [Prerequisites](#prerequisites)
6. [Installation & Setup](#installation--setup)
7. [Environment Variable Configuration](#environment-variable-configuration)
8. [Database Setup](#database-setup)
9. [Running the Application](#running-the-application)
10. [Authentication Workflow & Architecture](#authentication-workflow--architecture)
11. [Protected Routes & Session Management](#protected-routes--session-management)
12. [Security Implementation Details](#security-implementation-details)
13. [Testing & Verification](#testing--verification)
14. [Documentation Links](#documentation-links)
15. [Demo Video & Recording Instructions](#demo-video--recording-instructions)
16. [Known Limitations & Future Improvements](#known-limitations--future-improvements)

---

## Project Overview

The **Secure User Authentication System** is an enterprise-grade web application developed to handle user registration, credential verification, session management, and protected resource routing. Built following strict OWASP Top 10 guidelines and application security best practices, the system prevents XSS, NoSQL injection, brute-force attacks, timing side-channels, and session replay attacks.

---

## Key Features

- **Isolated Authentication Module:** Organized into distinct controllers, services, middleware, routes, and validation schemas (`backend/src/modules/auth/`).
- **Cryptographic Password Storage:** Passwords hashed with `bcrypt` using 12 salt rounds (`BCRYPT_SALT_ROUNDS >= 12`); constant-time verification via `bcrypt.compare()`.
- **Strict Input Validation & Sanitization:** Strips HTML, control characters, enforces RFC-compliant emails, and blocks NoSQL operator injection (`$` and `.`).
- **Dual Session Mechanism:** Primary delivery via signed, `HttpOnly`, `SameSite=Lax` cookies, with seamless `Authorization: Bearer <jwt>` fallback for API and mobile clients.
- **Server-Side Token Revocation:** Instant session invalidation on logout using a TTL-indexed MongoDB revocation collection (`RevokedToken`).
- **Account Lockout & Progressive Delay:** Automatically locks accounts for 15 minutes after 5 consecutive failed login attempts to prevent brute-force attacks.
- **Token Versioning:** Monotonically incrementing `tokenVersion` counter ensures password changes immediately invalidate older active sessions across all devices.
- **Server-Side Protected Page Guard:** Unauthenticated access to `/dashboard` triggers an immediate 302 redirect to the login page with strict anti-caching headers (`Cache-Control: no-store`).
- **Minimal, User-Centric Dashboard:** Authenticated users see only their registered name and email address, keeping personal data private and uncluttered.
- **Modern Responsive UI:** Custom 3D Claymorphism and Frosted Glassmorphism design with a photorealistic cloud-sky background.

---

## Technology Stack

- **Backend Runtime:** Node.js `>= 20.x`
- **Web Framework:** Express.js 4.x
- **Database:** MongoDB via Mongoose 8.x (with optional ephemeral in-memory MongoDB for zero-install development)
- **Password Hashing:** `bcryptjs` (Cost factor: 12 salt rounds)
- **Session Tokens:** `jsonwebtoken` (HMAC-SHA256 / HS256, UUIDv4 JTI nonces)
- **Security Headers:** `helmet` (Strict Content-Security-Policy, anti-sniff, anti-clickjacking)
- **Rate Limiting:** `express-rate-limit`
- **Frontend:** Responsive HTML5, Vanilla JavaScript (ES6 Fetch API), and custom CSS3 Glassmorphism/Claymorphism
- **Automated Testing:** Jest 29, Supertest, and `mongodb-memory-server`

---

## Repository & Project Structure

```text
Authentication-System/
├── backend/
│   ├── .env.example                    # Backend environment template
│   └── src/
│       ├── config/
│       │   ├── env.js                  # Environment parsing & production guards
│       │   └── db.js                   # MongoDB connection & in-memory runner
│       ├── models/
│       │   ├── User.js                 # User schema (roles, lockout, tokenVersion)
│       │   └── RevokedToken.js         # TTL-indexed JWT blacklist
│       ├── modules/
│       │   └── auth/                   # Dedicated modular authentication system
│       │       ├── auth.controller.js  # HTTP handlers & cookie management
│       │       ├── auth.service.js     # Bcrypt, JWT signing, and lockout logic
│       │       ├── auth.routes.js      # Express router & rate-limiting
│       │       ├── auth.middleware.js  # authenticate, protectPage & requireRole
│       │       └── auth.validation.js  # Sanitization & input validation schemas
│       ├── app.js                      # Express middleware, security, and routing
│       └── server.js                   # Application lifecycle & graceful shutdown
├── frontend/
│   ├── index.html                      # Sign In page (/ and /login)
│   ├── register.html                   # Create Account page (/register)
│   ├── dashboard.html                  # Authenticated Dashboard (/dashboard)
│   ├── styles.css                      # 3D Claymorphism & Glassmorphism styles
│   ├── app.js                          # Fetch API client, state, and route handlers
│   └── assets/
│       └── background.jpg              # High-resolution sky & cloud background
├── docs/
│   ├── API_DOCUMENTATION.md            # Detailed REST API specification
│   ├── SECURITY_AUDIT.md               # 20-point security audit report
│   ├── REQUIREMENTS_CHECKLIST.md       # Requirement-by-requirement verification
│   ├── TESTING_REPORT.md               # Automated and E2E test results
│   └── demo/
│       ├── DEMO_SCRIPT.md              # 9-step click-by-click video recording guide
│       ├── WALKTHROUGH.md              # Screenshot walkthrough of all user states
│       └── screenshots/                # Captured high-res demonstration states
├── tests/
│   ├── auth.test.js                    # 27 automated Jest integration tests
│   └── manual-verify.js                # 9-step native HTTP verification script
├── .env.example                        # Root-level configuration template
├── .gitignore                          # Strict git exclusion rules (no secrets)
├── package.json                        # Dependencies, scripts, and engine specs
└── README.md                           # Main documentation and guide
```

---

## Prerequisites

- **Node.js** version `20.x` or higher (verified on Node.js `v22.x` and `v24.x`).
- **npm** (bundled with Node.js).
- **MongoDB** (Local instance `mongodb://127.0.0.1:27017` or MongoDB Atlas cloud URI).
  *Note: If MongoDB is not installed locally, the server provides an integrated, zero-configuration in-memory MongoDB instance for development.*

---

## Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/anfasmohammed001-star/Authentication-System.git
   cd Authentication-System
   ```

2. **Install Dependencies:**
   ```bash
   npm install
   ```

3. **Configure Environment Variables:**
   Copy `.env.example` to `.env`:
   ```bash
   # Windows (PowerShell)
   Copy-Item .env.example .env

   # Linux / macOS
   cp .env.example .env
   ```

---

## Environment Variable Configuration

Edit `.env` (or `backend/.env`) to configure your environment:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `NODE_ENV` | `development` | Runtime mode (`development`, `test`, `production`). |
| `PORT` | `5000` | Port for Express web and API server. |
| `MONGO_URI` | `mongodb://127.0.0.1:27017/secure_auth_system` | MongoDB connection connection string. |
| `USE_IN_MEMORY_DB` | `true` | Set to `true` to run an in-memory database if MongoDB is not installed. |
| `JWT_SECRET` | `replace_this_with_...` | Cryptographic secret for signing JWTs (`>= 32` characters in prod). |
| `JWT_EXPIRES_IN` | `1h` | Token validity duration. |
| `JWT_ISSUER` | `secure-auth-system` | Standard JWT issuer claim. |
| `JWT_AUDIENCE` | `secure-auth-client` | Standard JWT audience claim. |
| `COOKIE_NAME` | `auth_token` | Name of the session cookie. |
| `COOKIE_SAME_SITE` | `lax` | SameSite cookie policy (`lax`, `strict`, `none`). |
| `COOKIE_SECURE` | `false` | Set to `true` in production to enforce HTTPS-only cookies. |
| `BCRYPT_SALT_ROUNDS` | `12` | Bcrypt hashing work factor (minimum 12). |
| `CORS_ORIGIN` | `http://localhost:5000` | Comma-separated list of allowed CORS origins. |
| `AUTH_RATE_LIMIT_WINDOW_MS`| `900000` | Rate limiting sliding window in ms (15 minutes). |
| `AUTH_RATE_LIMIT_MAX` | `20` | Max auth requests per IP within the window. |

---

## Database Setup

### Option A: Automatic In-Memory Database (Fastest / Zero Setup)
Leave `USE_IN_MEMORY_DB=true` in your `.env`. When you start the server, an ephemeral in-memory MongoDB instance will automatically launch.

### Option B: Local MongoDB
Install MongoDB Community Server, ensure the service is running (`mongod`), and set:
```env
USE_IN_MEMORY_DB=false
MONGO_URI=mongodb://127.0.0.1:27017/secure_auth_system
```

### Option C: MongoDB Atlas Cloud
Create a free MongoDB Atlas cluster and set:
```env
USE_IN_MEMORY_DB=false
MONGO_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/secure_auth_system?retryWrites=true&w=majority
```

---

## Running the Application

### Development Mode:
```bash
npm run dev
# or
npm start
```
The application will start at **`http://localhost:5000`**.

Open your browser and navigate to:
- **Sign In:** `http://localhost:5000/login` (or `http://localhost:5000`)
- **Register:** `http://localhost:5000/register`
- **Dashboard:** `http://localhost:5000/dashboard`

---

## Authentication Workflow & Architecture

```mermaid
sequenceDiagram
    autonumber
    actor User as Client Browser
    participant App as Express Web Server
    participant Auth as Auth Module (Middleware & Service)
    participant DB as MongoDB Database

    User->>App: POST /api/auth/register (username, email, password)
    App->>Auth: Sanitize inputs & validate schema
    Auth->>DB: Check for duplicate email or username
    Auth->>Auth: Hash password with bcrypt (12 rounds)
    Auth->>DB: Persist User (role=user, tokenVersion=0)
    Auth-->>User: 201 Created (safe user object; no passwordHash)

    User->>App: POST /api/auth/login (identifier, password)
    App->>Auth: Validate credentials
    Auth->>DB: Query user by email or username
    Auth->>Auth: Constant-time bcrypt.compare()
    Auth->>Auth: Mint JWT (HS256, jti, tokenVersion)
    Auth-->>User: 200 OK + Set-Cookie: auth_token (HttpOnly, SameSite=Lax)

    User->>App: GET /dashboard (Protected Page)
    App->>Auth: protectPage middleware checks cookie
    Auth->>Auth: Verify JWT signature & expiration
    Auth->>DB: Check blacklist (RevokedToken) & tokenVersion
    Auth-->>User: 200 OK (Render Dashboard HTML)

    User->>App: POST /api/auth/logout
    App->>Auth: logout()
    Auth->>DB: Insert jti into RevokedToken (TTL index)
    Auth-->>User: 200 OK + Clear-Cookie: auth_token
```

---

## Protected Routes & Session Management

### Protected API Routes
- **`GET /api/auth/me`:** Validates session and returns the current user profile.
- **`GET /api/dashboard`:** Returns authenticated user metrics.
- **`GET /api/auth/admin/*`:** RBAC-protected endpoint requiring `admin` role.

### Protected Web Pages
- **`GET /dashboard`:** Guarded by `protectPage` middleware.
  - If a valid session cookie exists: Serves `dashboard.html` with `Cache-Control: no-store` headers.
  - If unauthenticated or token is expired/revoked: Responds with `302 Found` redirecting the browser to `/?reason=auth_required`.

### Session Revocation
When a user logs out (`POST /api/auth/logout`), the server:
1. Clears the client-side `auth_token` cookie via `res.clearCookie()`.
2. Persists the token's unique `jti` in the MongoDB `RevokedToken` collection with a TTL index equal to the token's remaining lifetime.
3. Any attempt to replay the token header or cookie receives an immediate `401 Unauthorized` (`TOKEN_REVOKED`).

---

## API Endpoints Specification

Base URL: `http://localhost:5000` (Local) / `https://signauthe.netlify.app` (Production)

All API responses follow a consistent JSON envelope with a boolean `success` field. Passwords and `passwordHash` values are **never** logged or returned by any endpoint.

### Endpoints Summary Table

| Method | Path | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | No | Health check, server status, and database connectivity check |
| `POST` | `/api/auth/register` | No | Validate, sanitize, hash password (bcrypt 12 rounds), and register user |
| `POST` | `/api/auth/login` | No | Verify credentials in constant time, enforce lockout, and issue JWT cookie |
| `POST` | `/api/auth/logout` | Optional | Revoke active JWT server-side and clear `HttpOnly` cookie |
| `POST` | `/api/auth/forgot-password` | No | Request single-use cryptographically secure reset token (anti-enumeration) |
| `POST` | `/api/auth/reset-password` | No | Reset password using valid token and invalidate previous sessions |
| `POST` | `/api/auth/change-password` | **Yes** | Change password with current password verification |
| `GET` | `/api/auth/me` | **Yes** | Retrieve authenticated user profile & session expiration |
| `GET` | `/api/dashboard` | **Yes** | Retrieve protected dashboard payload for authenticated user |
| `GET` | `/api/auth/admin/users` | **Yes (Admin)** | List registered users with pagination (RBAC enforced) |
| `GET` | `/api/auth/admin/stats` | **Yes (Admin)** | System security telemetry & configuration audit |

### 1. Register User — `POST /api/auth/register`
- **Request Body:**
  ```json
  {
    "username": "alice_dev",
    "email": "alice@example.com",
    "password": "StrongPassword#2026"
  }
  ```
- **Validation Rules:** Username 3–30 chars (`^[a-zA-Z0-9_-]+$`); email lowercased and RFC-validated; password >= 8 chars with uppercase, lowercase, number, and special character.
- **Success Response (`201 Created`):**
  ```json
  {
    "success": true,
    "message": "User registered successfully.",
    "data": {
      "user": {
        "id": "6732f48e1a2b3c4d5e6f7a8b",
        "username": "alice_dev",
        "email": "alice@example.com",
        "role": "user",
        "createdAt": "2026-11-12T01:56:03.000Z"
      }
    }
  }
  ```

### 2. User Login — `POST /api/auth/login`
- **Request Body:**
  ```json
  {
    "identifier": "alice@example.com",
    "password": "StrongPassword#2026"
  }
  ```
- **Behavior:** Accepts email or username. Enforces 5-attempt account lockout (15-min cooldown). Returns `Set-Cookie: auth_token=<jwt>; HttpOnly; SameSite=Lax; Path=/` and JSON Bearer token.
- **Success Response (`200 OK`):**
  ```json
  {
    "success": true,
    "message": "Login successful.",
    "data": {
      "user": { "id": "...", "username": "alice_dev", "email": "alice@example.com", "role": "user" },
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": "1h"
    }
  }
  ```

### 3. Session Verification — `GET /api/auth/me` (Protected)
- **Auth:** `auth_token` cookie or `Authorization: Bearer <jwt>`.
- **Success Response (`200 OK`):**
  ```json
  {
    "success": true,
    "data": {
      "user": { "id": "...", "username": "alice_dev", "email": "alice@example.com", "role": "user" },
      "session": { "expiresAt": "2026-11-12T02:56:03.000Z" }
    }
  }
  ```

### 4. Protected Dashboard — `GET /api/dashboard` (Protected)
- **Auth:** `auth_token` cookie or `Authorization: Bearer <jwt>`.
- **Success Response (`200 OK`):** Returns user profile, session details, and security controls.

### 5. Logout & Token Revocation — `POST /api/auth/logout`
- **Behavior:** Revokes token `jti` in database blacklist until expiration, clears `auth_token` cookie.
- **Success Response (`200 OK`):** `{ "success": true, "message": "Logged out successfully." }`

---

## Security Implementation Details

- **Password Hashing:** Minimum 12 salt rounds enforced. Plaintext passwords never enter the database or logs.
- **Input Sanitization:** HTML tags, quotes, backticks, and control characters are stripped from user inputs to prevent XSS.
- **NoSQL Injection Defense:** `sanitizeRequestMiddleware` recursively detects and blocks keys containing `$` or `.`. Non-string payloads for username/password are strictly rejected.
- **Brute-Force & Credential Stuffing Prevention:**
  - IP-based rate limiting (20 requests per 15 minutes).
  - Account lockout after 5 consecutive failed login attempts (15-minute freeze, returning `423 Locked`).
- **Timing Attack Mitigation:** Password verification executes constant-time hash comparisons. Non-existent accounts trigger a simulated hash comparison to prevent response timing discrepancy.
- **Safe Error Normalization:** Generic messages (`"Invalid email/username or password."`) prevent username harvesting.

---

## Testing & Verification

Run the full automated test suite (27 integration tests across all auth modules):
```bash
npm test
```

Run the standalone end-to-end verification script against the live server:
```bash
node tests/manual-verify.js
```

### Test Suite Summary:
- **Registration:** Normalization, bcrypt work factor, case-insensitive duplicate checks, missing fields, XSS payloads, password strength checklist, NoSQL operator blocking.
- **Login:** Identifier flexibility (email or username), wrong password rejection, non-existent account handling, NoSQL object injection blocking.
- **Protected Routes:** Cookie validation, Bearer header fallback, missing token rejection, tampered token rejection, expired token rejection, HTML server-side redirection.
- **Session Revocation:** Server-side blacklist insertion, cookie clearing, replay prevention.
- **Account Lockout:** 5-attempt counter, lockout enforcement, progressive timeout.
- **Password Reset:** Single-use cryptographic reset tokens, session invalidation via `tokenVersion`.
- **RBAC:** Privilege escalation prevention, role authorization on admin endpoints.

---

## Documentation Links

- [**Security Audit Report**](docs/SECURITY_AUDIT.md): 20-point code-level security review covering password hashing, session tokens, injection guards, and secret isolation.
- [**Requirements Verification Checklist**](docs/REQUIREMENTS_CHECKLIST.md): Official deliverable and evaluation checklist with PASS / FAIL statuses and verification methods.
- [**Testing & Verification Report**](docs/TESTING_REPORT.md): Detailed output from automated Jest suites and live HTTP integration tests.

---

## Demo Video & Recording Instructions

- [**Video Recording Script**](docs/demo/DEMO_SCRIPT.md): Complete timed, click-by-click script with narration instructions covering the 9 required demo steps.
- [**Visual Walkthrough**](docs/demo/WALKTHROUGH.md): Step-by-step visual demonstration with high-resolution screenshot captures of all authentication states.

---

## Known Limitations & Future Improvements

- **Multi-Factor Authentication (MFA/TOTP):** While single-use password resets and secure sessions are implemented, authenticator-app-based TOTP (e.g. Google Authenticator) can be added in future releases for additional assurance.
- **OAuth2 / Social Logins:** The current architecture focuses strictly on zero-trust local credentials; OpenID Connect / OAuth2 (Google, GitHub) providers can be integrated via Passport.js or native OAuth flows.
- **Distributed Session Blacklisting:** For high-traffic horizontally scaled multi-region clusters, the MongoDB TTL blacklist can be mirrored to Redis for sub-millisecond revocation lookups.
