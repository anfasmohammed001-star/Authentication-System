process.env.NODE_ENV = 'test';
process.env.AUTH_RATE_LIMIT_MAX = '1000';

const request = require('supertest');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

const app = require('../backend/src/app');
const env = require('../backend/src/config/env');
const User = require('../backend/src/models/User');
const RevokedToken = require('../backend/src/models/RevokedToken');

let mongoServer;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri());
});

afterEach(async () => {
  await User.deleteMany({});
  await RevokedToken.deleteMany({});
});

afterAll(async () => {
  await mongoose.disconnect();
  if (mongoServer) {
    await mongoServer.stop();
  }
});

const validUser = {
  username: 'alice_dev',
  email: 'alice@example.com',
  password: 'StrongPassword#2026',
};

describe('Authentication System Integration Tests', () => {
  describe('POST /api/auth/register', () => {
    it('registers a valid user, normalizes/trims inputs, hashes password with bcrypt (>=12 rounds), and hides passwordHash', async () => {
      const res = await request(app).post('/api/auth/register').send({
        username: '  alice_dev  ',
        email: '  ALICE.Dev@Example.COM  ',
        password: validUser.password,
      });

      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.user).toMatchObject({
        username: 'alice_dev',
        email: 'alice.dev@example.com',
      });
      expect(res.body.data.user.id).toBeDefined();
      expect(res.body.data.user.createdAt).toBeDefined();
      expect(res.body.data.user.password).toBeUndefined();
      expect(res.body.data.user.passwordHash).toBeUndefined();

      const stored = await User.findOne({ email: 'alice.dev@example.com' }).select('+passwordHash');
      expect(stored).not.toBeNull();
      expect(stored.passwordHash).not.toBe(validUser.password);
      expect(stored.passwordHash.startsWith('$2')).toBe(true);
      const rounds = bcrypt.getRounds(stored.passwordHash);
      expect(rounds).toBeGreaterThanOrEqual(12);
      const isMatch = await bcrypt.compare(validUser.password, stored.passwordHash);
      expect(isMatch).toBe(true);
    });

    it('rejects duplicate email registration with 409 Conflict (case-insensitive)', async () => {
      await request(app).post('/api/auth/register').send(validUser).expect(201);

      const res = await request(app).post('/api/auth/register').send({
        username: 'another_user',
        email: '  ALICE@EXAMPLE.COM ',
        password: validUser.password,
      });

      expect(res.statusCode).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.code).toBe('DUPLICATE_EMAIL');
    });

    it('rejects duplicate username registration with 409 Conflict (case-insensitive)', async () => {
      await request(app).post('/api/auth/register').send(validUser).expect(201);

      const res = await request(app).post('/api/auth/register').send({
        username: 'Alice_Dev',
        email: 'different@example.com',
        password: validUser.password,
      });

      expect(res.statusCode).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.code).toBe('DUPLICATE_USERNAME');
    });

    it('rejects missing fields with 400 Bad Request', async () => {
      const res = await request(app).post('/api/auth/register').send({
        username: 'only_name',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.code).toBe('VALIDATION_ERROR');
      expect(Array.isArray(res.body.errors)).toBe(true);
      expect(res.body.errors.length).toBeGreaterThanOrEqual(2);
    });

    it('rejects invalid email format and XSS payloads in username with 400 Bad Request', async () => {
      const res = await request(app).post('/api/auth/register').send({
        username: '<script>alert(1)</script>',
        email: 'not-an-email',
        password: validUser.password,
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.errors.some((e) => e.field === 'username')).toBe(true);
      expect(res.body.errors.some((e) => e.field === 'email')).toBe(true);
    });

    it('rejects weak passwords and >72-byte passwords with 400 Bad Request', async () => {
      const weakRes = await request(app).post('/api/auth/register').send({
        username: 'valid_user',
        email: 'valid@example.com',
        password: 'weakpassword',
      });
      expect(weakRes.statusCode).toBe(400);

      const tooLongRes = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'valid_user',
          email: 'valid@example.com',
          password: `Aa1!${'x'.repeat(70)}`,
        });
      expect(tooLongRes.statusCode).toBe(400);
    });

    it('blocks NoSQL operator injection objects in registration payload', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'hacker_user',
          email: { $ne: null },
          password: validUser.password,
        });

      expect(res.statusCode).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      await request(app).post('/api/auth/register').send(validUser).expect(201);
    });

    it('logs in with valid email and password, sets HttpOnly SameSite cookie, and returns JWT + safe user', async () => {
      const res = await request(app).post('/api/auth/login').send({
        email: '  ALICE@example.com ',
        password: validUser.password,
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.token).toBeTruthy();
      expect(res.body.data.user).toMatchObject({
        username: validUser.username,
        email: validUser.email,
      });
      expect(res.body.data.user.passwordHash).toBeUndefined();

      const setCookie = res.headers['set-cookie'];
      expect(Array.isArray(setCookie)).toBe(true);
      expect(setCookie[0]).toContain(`${env.cookieName}=`);
      expect(setCookie[0]).toContain('HttpOnly');
      expect(setCookie[0]).toContain('SameSite=Lax');
    });

    it('logs in with username via identifier field', async () => {
      const res = await request(app).post('/api/auth/login').send({
        identifier: 'alice_dev',
        password: validUser.password,
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.data.user.username).toBe(validUser.username);
    });

    it('returns 401 Unauthorized for wrong password', async () => {
      const res = await request(app).post('/api/auth/login').send({
        email: validUser.email,
        password: 'WrongPassword#999',
      });

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.code).toBe('INVALID_CREDENTIALS');
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('returns 401 Unauthorized for non-existent email', async () => {
      const res = await request(app).post('/api/auth/login').send({
        email: 'nobody@example.com',
        password: validUser.password,
      });

      expect(res.statusCode).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.code).toBe('INVALID_CREDENTIALS');
    });

    it('returns 400 Bad Request for missing fields or NoSQL injection objects', async () => {
      const missingRes = await request(app).post('/api/auth/login').send({
        email: validUser.email,
      });
      expect(missingRes.statusCode).toBe(400);

      const nosqlRes = await request(app)
        .post('/api/auth/login')
        .send({
          email: { $gt: '' },
          password: { $ne: '' },
        });
      expect(nosqlRes.statusCode).toBe(400);
    });
  });

  describe('Protected Routes & Auth Middleware (/api/auth/me, /api/dashboard, /dashboard)', () => {
    let authToken;
    let authCookies;

    beforeEach(async () => {
      await request(app).post('/api/auth/register').send(validUser).expect(201);
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ email: validUser.email, password: validUser.password })
        .expect(200);

      authToken = loginRes.body.data.token;
      authCookies = loginRes.headers['set-cookie'];
    });

    it('allows access to GET /api/auth/me and GET /api/dashboard with valid HttpOnly cookie', async () => {
      const meRes = await request(app).get('/api/auth/me').set('Cookie', authCookies);
      expect(meRes.statusCode).toBe(200);
      expect(meRes.body.data.user.email).toBe(validUser.email);
      expect(meRes.body.data.user.username).toBe(validUser.username);
      expect(meRes.body.data.user.passwordHash).toBeUndefined();

      const dashRes = await request(app).get('/api/dashboard').set('Cookie', authCookies);
      expect(dashRes.statusCode).toBe(200);
      expect(dashRes.body.data.user.username).toBe(validUser.username);
      expect(dashRes.body.data.securityProfile.revocationEnabled).toBe(true);
    });

    it('allows access to GET /api/auth/me with Authorization: Bearer token fallback', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.data.user.email).toBe(validUser.email);
    });

    it('rejects missing token with 401 Unauthorized', async () => {
      const res = await request(app).get('/api/auth/me');
      expect(res.statusCode).toBe(401);
      expect(res.body.code).toBe('MISSING_TOKEN');
    });

    it('rejects tampered or malformed tokens with 401 Unauthorized', async () => {
      const tampered = `${authToken.slice(0, -5)}xxxxx`;
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${tampered}`);

      expect(res.statusCode).toBe(401);
      expect(res.body.code).toBe('INVALID_TOKEN');

      const wrongSecretToken = jwt.sign(
        { sub: '123', jti: 'fake-jti' },
        'wrong_secret',
        { issuer: env.jwtIssuer, audience: env.jwtAudience, expiresIn: '1h' }
      );
      const wrongRes = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${wrongSecretToken}`);
      expect(wrongRes.statusCode).toBe(401);
    });

    it('rejects expired tokens with 401 Unauthorized', async () => {
      const user = await User.findOne({ email: validUser.email });
      const expiredToken = jwt.sign(
        { sub: user._id.toString(), username: user.username, email: user.email, jti: 'exp-jti-1' },
        env.jwtSecret,
        {
          algorithm: 'HS256',
          issuer: env.jwtIssuer,
          audience: env.jwtAudience,
          expiresIn: -10,
        }
      );

      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect(res.statusCode).toBe(401);
      expect(res.body.code).toBe('TOKEN_EXPIRED');
    });

    it('protects GET /dashboard page by redirecting unauthenticated HTML requests and serving with no-store when authenticated', async () => {
      const unauthRes = await request(app)
        .get('/dashboard')
        .set('Accept', 'text/html');
      expect(unauthRes.statusCode).toBe(302);
      expect(unauthRes.headers.location).toBe('/?reason=auth_required');

      const authRes = await request(app)
        .get('/dashboard')
        .set('Accept', 'text/html')
        .set('Cookie', authCookies);
      expect(authRes.statusCode).toBe(200);
      expect(authRes.headers['cache-control']).toContain('no-store');
      expect(authRes.text).toContain('Dashboard');
      expect(authRes.text).toContain('Logout');
    });
  });

  describe('POST /api/auth/logout & Token Invalidation', () => {
    it('clears the HttpOnly cookie and revokes the JWT server-side so replaying it fails with 401', async () => {
      const agent = request.agent(app);

      await agent.post('/api/auth/register').send(validUser).expect(201);
      const loginRes = await agent
        .post('/api/auth/login')
        .send({ email: validUser.email, password: validUser.password })
        .expect(200);

      const issuedToken = loginRes.body.data.token;

      // Confirm authenticated access works before logout
      await agent.get('/api/auth/me').expect(200);

      // Logout
      const logoutRes = await agent.post('/api/auth/logout').expect(200);
      expect(logoutRes.body.success).toBe(true);
      const clearedCookie = logoutRes.headers['set-cookie'][0];
      expect(clearedCookie).toContain(`${env.cookieName}=;`);

      // Cookie jar is cleared -> rejected
      const afterCookieRes = await agent.get('/api/auth/me');
      expect(afterCookieRes.statusCode).toBe(401);

      // Replaying the exact same Bearer JWT after logout -> also rejected (revoked server-side)
      const replayRes = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${issuedToken}`);
      expect(replayRes.statusCode).toBe(401);
      expect(replayRes.body.code).toBe('TOKEN_REVOKED');
    });

    it('handles unauthenticated logout calls gracefully and idempotently', async () => {
      const res = await request(app).post('/api/auth/logout');
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  describe('Account Lockout Protection & Progressive Delay', () => {
    it('locks account after 5 consecutive failed login attempts and unlocks after timeout', async () => {
      await request(app).post('/api/auth/register').send(validUser).expect(201);

      // 4 consecutive bad attempts
      for (let i = 0; i < 4; i += 1) {
        const res = await request(app)
          .post('/api/auth/login')
          .send({ identifier: validUser.email, password: 'WrongPassword#123' });
        expect(res.statusCode).toBe(401);
        expect(res.body.code).toBe('INVALID_CREDENTIALS');
      }

      // 5th bad attempt -> locks account
      const fifthRes = await request(app)
        .post('/api/auth/login')
        .send({ identifier: validUser.email, password: 'WrongPassword#123' });
      expect(fifthRes.statusCode).toBe(401);

      // 6th attempt (even with correct password) -> 423 Locked
      const lockedRes = await request(app)
        .post('/api/auth/login')
        .send({ identifier: validUser.email, password: validUser.password });
      expect(lockedRes.statusCode).toBe(423);
      expect(lockedRes.body.code).toBe('ACCOUNT_LOCKED');
      expect(lockedRes.body.message).toContain('Account is temporarily locked');

      // Fast-forward lockout expiration in database
      await User.updateOne({ email: validUser.email }, { lockUntil: new Date(Date.now() - 1000) });

      // Correct password now succeeds and resets lockout counter
      const successRes = await request(app)
        .post('/api/auth/login')
        .send({ identifier: validUser.email, password: validUser.password });
      expect(successRes.statusCode).toBe(200);
      expect(successRes.body.success).toBe(true);

      const dbUser = await User.findOne({ email: validUser.email });
      expect(dbUser.failedLoginAttempts).toBe(0);
      expect(dbUser.lockUntil).toBeNull();
    });
  });

  describe('Password Reset & Account Management', () => {
    it('generates secure single-use reset token and resets password, invalidating older sessions', async () => {
      await request(app).post('/api/auth/register').send(validUser).expect(201);

      // Login to get an active token
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ identifier: validUser.email, password: validUser.password })
        .expect(200);
      const originalToken = loginRes.body.data.token;

      // 1. Forgot password request (returns generic message for security, plus test token)
      const forgotRes = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: validUser.email });
      expect(forgotRes.statusCode).toBe(200);
      expect(forgotRes.body.success).toBe(true);
      expect(forgotRes.body.resetToken).toBeDefined();

      const resetToken = forgotRes.body.resetToken;

      // 2. Reject reset with weak password
      const weakResetRes = await request(app)
        .post('/api/auth/reset-password')
        .send({ token: resetToken, newPassword: 'weak' });
      expect(weakResetRes.statusCode).toBe(400);

      // 3. Complete valid password reset
      const newPassword = 'NewSecretPassword#2027';
      const resetRes = await request(app)
        .post('/api/auth/reset-password')
        .send({ token: resetToken, newPassword });
      expect(resetRes.statusCode).toBe(200);
      expect(resetRes.body.success).toBe(true);

      // 4. Token cannot be reused (single-use enforcement)
      const reuseRes = await request(app)
        .post('/api/auth/reset-password')
        .send({ token: resetToken, newPassword: 'AnotherPassword#2028' });
      expect(reuseRes.statusCode).toBe(400);
      expect(reuseRes.body.code).toBe('INVALID_RESET_TOKEN');

      // 5. Old session token is now invalidated by passwordChangedAt
      const oldSessionRes = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${originalToken}`);
      expect(oldSessionRes.statusCode).toBe(401);
      expect(oldSessionRes.body.code).toBe('TOKEN_INVALIDATED');

      // 6. Login succeeds with new password and fails with old password
      await request(app)
        .post('/api/auth/login')
        .send({ identifier: validUser.email, password: validUser.password })
        .expect(401);

      await request(app)
        .post('/api/auth/login')
        .send({ identifier: validUser.email, password: newPassword })
        .expect(200);
    });

    it('allows authenticated users to change password with current password verification', async () => {
      await request(app).post('/api/auth/register').send(validUser).expect(201);
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ identifier: validUser.email, password: validUser.password })
        .expect(200);
      const token = loginRes.body.data.token;

      // Bad current password -> 401
      const badCurrentRes = await request(app)
        .post('/api/auth/change-password')
        .set('Authorization', `Bearer ${token}`)
        .send({ currentPassword: 'WrongCurrentPassword#1', newPassword: 'BrandNewPassword#999' });
      expect(badCurrentRes.statusCode).toBe(401);

      // Same password as current -> 400
      const sameRes = await request(app)
        .post('/api/auth/change-password')
        .set('Authorization', `Bearer ${token}`)
        .send({ currentPassword: validUser.password, newPassword: validUser.password });
      expect(sameRes.statusCode).toBe(400);

      // Valid change password -> 200
      const validChangeRes = await request(app)
        .post('/api/auth/change-password')
        .set('Authorization', `Bearer ${token}`)
        .send({ currentPassword: validUser.password, newPassword: 'BrandNewPassword#999' });
      expect(validChangeRes.statusCode).toBe(200);
      expect(validChangeRes.body.success).toBe(true);
    });
  });

  describe('Role-Based Access Control (RBAC) & Admin Authorization', () => {
    it('enforces default role=user during registration and prevents privilege escalation', async () => {
      const regRes = await request(app).post('/api/auth/register').send({
        ...validUser,
        role: 'admin',
        isAdmin: true,
      });

      expect(regRes.statusCode).toBe(201);
      expect(regRes.body.data.user.role).toBe('user');

      const dbUser = await User.findOne({ email: validUser.email });
      expect(dbUser.role).toBe('user');
    });

    it('rejects unauthenticated requests to admin endpoints with 401', async () => {
      const res = await request(app).get('/api/auth/admin/users');
      expect(res.statusCode).toBe(401);
      expect(res.body.code).toBe('MISSING_TOKEN');
    });

    it('rejects standard users with 403 Forbidden on admin endpoints', async () => {
      await request(app).post('/api/auth/register').send(validUser).expect(201);
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ identifier: validUser.email, password: validUser.password })
        .expect(200);

      const res = await request(app)
        .get('/api/auth/admin/users')
        .set('Authorization', `Bearer ${loginRes.body.data.token}`);

      expect(res.statusCode).toBe(403);
      expect(res.body.code).toBe('FORBIDDEN');
    });

    it('allows admin users access to admin endpoints', async () => {
      await request(app).post('/api/auth/register').send(validUser).expect(201);
      // Promote user in database securely
      await User.updateOne({ email: validUser.email }, { role: 'admin' });

      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ identifier: validUser.email, password: validUser.password })
        .expect(200);

      expect(loginRes.body.data.user.role).toBe('admin');

      const usersRes = await request(app)
        .get('/api/auth/admin/users')
        .set('Authorization', `Bearer ${loginRes.body.data.token}`);

      expect(usersRes.statusCode).toBe(200);
      expect(usersRes.body.success).toBe(true);
      expect(usersRes.body.data.total).toBe(1);
      expect(usersRes.body.data.users[0].username).toBe(validUser.username);

      const statsRes = await request(app)
        .get('/api/auth/admin/stats')
        .set('Authorization', `Bearer ${loginRes.body.data.token}`);

      expect(statsRes.statusCode).toBe(200);
      expect(statsRes.body.data.rbacEnforced).toBe(true);
    });
  });
});

