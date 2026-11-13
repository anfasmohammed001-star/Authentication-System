/**
 * End-to-End Verification Script (Step 11)
 *
 * Tests the complete authentication lifecycle against either:
 *   1. A running server specified by TARGET_URL (e.g., TARGET_URL=http://localhost:5000 node tests/manual-verify.js)
 *   2. An automatic ephemeral server + in-memory MongoDB spun up by this script when TARGET_URL is not set.
 */

const assert = require('assert');
const http = require('http');

const externalTarget = process.env.TARGET_URL ? process.env.TARGET_URL.replace(/\/$/, '') : null;

async function runVerification(baseUrl) {
  const uniqueSuffix = Date.now();
  const testUser = {
    username: `verify_user_${uniqueSuffix}`,
    email: `verify_${uniqueSuffix}@example.com`,
    password: 'VerifyPass#2026',
  };

  let passed = 0;
  let failed = 0;

  async function check(label, fn) {
    try {
      await fn();
      passed += 1;
      console.log(`[PASS] ${label}`);
    } catch (err) {
      failed += 1;
      console.error(`[FAIL] ${label}: ${err.message}`);
    }
  }

  console.log(`\nRunning end-to-end verification against ${baseUrl}\n`);

  await check('1. Missing fields on registration returns 400 Bad Request', async () => {
    const res = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'incomplete' }),
    });
    assert.strictEqual(res.status, 400);
  });

  await check('2. Valid registration returns 201 Created without exposing passwordHash', async () => {
    const res = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: `  ${testUser.username}  `,
        email: `  ${testUser.email.toUpperCase()}  `,
        password: testUser.password,
      }),
    });
    const body = await res.json();
    assert.strictEqual(res.status, 201);
    assert.strictEqual(body.success, true);
    assert.strictEqual(body.data.user.username, testUser.username);
    assert.strictEqual(body.data.user.email, testUser.email);
    assert.strictEqual(body.data.user.passwordHash, undefined);
  });

  await check('3. Duplicate email registration returns 409 Conflict', async () => {
    const res = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: `other_${uniqueSuffix}`,
        email: testUser.email,
        password: testUser.password,
      }),
    });
    assert.strictEqual(res.status, 409);
  });

  await check('4. Unauthorized GET /api/auth/me returns 401 Unauthorized', async () => {
    const res = await fetch(`${baseUrl}/api/auth/me`);
    assert.strictEqual(res.status, 401);
  });

  await check('5. Unauthenticated GET /dashboard redirects (302) to login page', async () => {
    const res = await fetch(`${baseUrl}/dashboard`, {
      redirect: 'manual',
      headers: { Accept: 'text/html' },
    });
    assert.strictEqual(res.status, 302);
    assert(res.headers.get('location').startsWith('/?reason=auth_required'));
  });

  await check('6. Wrong password login returns 401 Unauthorized', async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testUser.email,
        password: 'WrongPassword#999',
      }),
    });
    assert.strictEqual(res.status, 401);
  });

  let sessionCookie = '';
  let bearerToken = '';

  await check('7. Valid login returns 200 OK with HttpOnly cookie and JWT', async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testUser.email,
        password: testUser.password,
      }),
    });
    const body = await res.json();
    assert.strictEqual(res.status, 200);
    assert.strictEqual(body.success, true);
    assert(body.data.token);
    bearerToken = body.data.token;

    const rawSetCookie = res.headers.get('set-cookie');
    assert(rawSetCookie && rawSetCookie.includes('HttpOnly'));
    sessionCookie = rawSetCookie.split(';')[0];
  });

  await check('8. Protected GET /api/auth/me & GET /dashboard succeed with session cookie', async () => {
    const meRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Cookie: sessionCookie },
    });
    const meBody = await meRes.json();
    assert.strictEqual(meRes.status, 200);
    assert.strictEqual(meBody.data.user.email, testUser.email);

    const dashRes = await fetch(`${baseUrl}/dashboard`, {
      headers: { Cookie: sessionCookie, Accept: 'text/html' },
    });
    assert.strictEqual(dashRes.status, 200);
  });

  await check('9. POST /api/auth/logout clears cookie and invalidates token server-side', async () => {
    const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: { Cookie: sessionCookie },
    });
    assert.strictEqual(logoutRes.status, 200);

    const replayBearerRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Authorization: `Bearer ${bearerToken}` },
    });
    assert.strictEqual(replayBearerRes.status, 401);

    const replayCookieRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Cookie: sessionCookie },
    });
    assert.strictEqual(replayCookieRes.status, 401);
  });

  console.log(`\nVerification Summary: ${passed} passed, ${failed} failed.\n`);
  return failed === 0;
}

async function main() {
  if (externalTarget) {
    const ok = await runVerification(externalTarget);
    process.exit(ok ? 0 : 1);
  }

  // Self-contained verification mode: boot app with ephemeral in-memory MongoDB
  process.env.NODE_ENV = 'test';
  process.env.AUTH_RATE_LIMIT_MAX = '1000';
  process.env.USE_IN_MEMORY_DB = 'true';

  const { connectDatabase, disconnectDatabase } = require('../backend/src/config/db');
  const app = require('../backend/src/app');

  await connectDatabase();
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  let ok = false;
  try {
    ok = await runVerification(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await disconnectDatabase();
  }

  process.exit(ok ? 0 : 1);
}

main().catch((err) => {
  console.error('[FATAL]', err);
  process.exit(1);
});

