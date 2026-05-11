# Auth Refactor: Session \u2192 JWT

Replaces session-based authentication with JWT (access + refresh token rotation) in an Express + TypeScript app.

## What's included

| Feature | Detail |
|---|---|
| `POST /auth/register` | Register with email/password. Password validated (8+ chars, upper, lower, digit). |
| `POST /auth/login` | Returns access token (15m) + refresh token (7d). |
| `POST /auth/refresh` | Token rotation: old refresh token is invalidated after use. |
| `POST /auth/logout` | Server-side revocation of all refresh tokens for the user. |
| `GET /protected` | Example protected route. |
| `authenticateToken` middleware | Validates Bearer JWT on protected routes. |

## Stack

- **Runtime:** Node.js 22, Express 4, TypeScript 5
- **Auth:** `jsonwebtoken` + `bcryptjs` (12 salt rounds)
- **Validation:** `express-validator`
- **Testing:** Jest + `ts-jest` + Supertest

## Setup

```bash
cp .env.example .env
# Fill in JWT_SECRET (min 32 chars)
npm install
npm run build
npm start
```

## Running tests

```bash
npm test
```

## Endpoints

All responses are JSON. Errors include `{ "error": "message" }`.

```
POST /auth/register   { email, password }              \u2192 201 { user, tokens }
POST /auth/login      { email, password }              \u2192 200 { user, tokens }
POST /auth/refresh    { refreshToken }                 \u2192 200 { tokens }
POST /auth/logout     (Bearer <accessToken>)           \u2192 200
GET  /protected       (Bearer <accessToken>)           \u2192 200 { message }
GET  /health                                           \u2192 200 { status }
```

## Token shapes

**Access token payload**
```json
{ "sub": "<userId>", "email": "...", "iat": ..., "exp": ... }
```

**Refresh token payload** (adds `jti` for rotation/revocation)
```json
{ "sub": "<userId>", "email": "...", "iat": ..., "exp": ..., "jti": "uuid" }
```
