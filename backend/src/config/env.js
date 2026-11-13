const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const dotenv = require('dotenv');

// Load backend/.env first if present, then fallback to root .env
const backendEnvPath = path.resolve(__dirname, '../../.env');
const rootEnvPath = path.resolve(__dirname, '../../../.env');

if (fs.existsSync(backendEnvPath)) {
  dotenv.config({ path: backendEnvPath });
} else if (fs.existsSync(rootEnvPath)) {
  dotenv.config({ path: rootEnvPath });
} else {
  dotenv.config();
}

const nodeEnv = process.env.NODE_ENV || 'development';
const isProduction = nodeEnv === 'production';
const isTest = nodeEnv === 'test';

function resolveJwtSecret() {
  const configured = process.env.JWT_SECRET ? process.env.JWT_SECRET.trim() : '';

  if (isProduction) {
    if (!configured || configured.length < 32 || configured.includes('replace_this')) {
      throw new Error(
        'FATAL: JWT_SECRET must be set to a strong secret (>= 32 chars) in production.'
      );
    }
    return configured;
  }

  if (configured && configured.length >= 16) {
    return configured;
  }

  if (isTest) {
    return 'test_only_jwt_secret_key_for_automated_integration_suite_do_not_use_in_prod';
  }

  // Ephemeral fallback for local development when .env has not been created yet
  console.warn(
    '[SECURITY WARNING] JWT_SECRET is not configured. Using a temporary development secret; set JWT_SECRET in backend/.env.'
  );
  return crypto.createHash('sha256').update(`dev-secret-${process.cwd()}`).digest('hex');
}

function parseDurationToMs(durationStr, fallbackMs = 3600000) {
  if (!durationStr || typeof durationStr !== 'string') return fallbackMs;
  const match = durationStr.trim().match(/^(\d+)([smhd])$/i);
  if (!match) return fallbackMs;

  const value = Number(match[1]);
  const unit = match[2].toLowerCase();
  const multipliers = {
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
  };
  return value * (multipliers[unit] || 1000);
}

const parsedRounds = Number.parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);
if (isProduction && (!Number.isFinite(parsedRounds) || parsedRounds < 12)) {
  throw new Error('FATAL: BCRYPT_SALT_ROUNDS must be >= 12 in production.');
}
const bcryptSaltRounds = Number.isFinite(parsedRounds) && parsedRounds >= 12 ? parsedRounds : 12;

const jwtExpiresIn = process.env.JWT_EXPIRES_IN || '1h';
const cookieMaxAgeMs = parseDurationToMs(jwtExpiresIn, 60 * 60 * 1000);

const allowedSameSite = new Set(['strict', 'lax', 'none']);
const rawSameSite = (process.env.COOKIE_SAME_SITE || 'lax').toLowerCase();
const cookieSameSite = allowedSameSite.has(rawSameSite) ? rawSameSite : 'lax';

const corsOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5000,http://127.0.0.1:5000')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

const env = Object.freeze({
  nodeEnv,
  isProduction,
  isTest,
  port: Number.parseInt(process.env.PORT || '5000', 10),
  mongoUri: process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/secure_auth_system',
  useInMemoryDb: !isProduction && process.env.USE_IN_MEMORY_DB === 'true',
  jwtSecret: resolveJwtSecret(),
  jwtExpiresIn,
  jwtIssuer: process.env.JWT_ISSUER || 'secure-auth-system',
  jwtAudience: process.env.JWT_AUDIENCE || 'secure-auth-client',
  cookieName: process.env.COOKIE_NAME || 'auth_token',
  cookieSameSite,
  cookieSecure: isProduction || process.env.COOKIE_SECURE === 'true',
  cookieMaxAgeMs,
  bcryptSaltRounds,
  corsOrigins,
  rateLimitWindowMs: Number.parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS || '900000', 10),
  rateLimitMax: Number.parseInt(
    process.env.AUTH_RATE_LIMIT_MAX || (isTest ? '1000' : '20'),
    10
  ),
});

module.exports = env;

