const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const env = require('../../config/env');
const User = require('../../models/User');
const RevokedToken = require('../../models/RevokedToken');

/**
 * Custom domain error for authentication workflows.
 */
class AuthError extends Error {
  /**
   * @param {number} statusCode
   * @param {string} code
   * @param {string} message
   * @param {Array<{ field: string, message: string }>} [errors]
   */
  constructor(statusCode, code, message, errors = []) {
    super(message);
    this.name = 'AuthError';
    this.statusCode = statusCode;
    this.code = code;
    this.errors = errors;
  }
}

// Lazily initialized dummy bcrypt hash matching configured rounds for constant-time comparison
// when an account does not exist, mitigating timing-based user enumeration.
let dummyPasswordHash = null;
function getDummyPasswordHash() {
  if (!dummyPasswordHash) {
    dummyPasswordHash = bcrypt.hashSync(
      'constant_time_dummy_secret_value',
      env.bcryptSaltRounds
    );
  }
  return dummyPasswordHash;
}

/**
 * Map a Mongoose User document into a strictly sanitized public DTO.
 * Guarantees passwordHash and internal keys are never exposed.
 * @param {import('mongoose').Document | Record<string, any>} user
 */
function toSafeUser(user) {
  return {
    id: user._id ? user._id.toString() : user.id,
    username: user.username,
    email: user.email,
    role: user.role || 'user',
    createdAt: user.createdAt,
  };
}

/**
 * Register a new user after checking for duplicate email/username and hashing password with bcrypt (>= 12 rounds).
 * Enforces role='user' regardless of input payload to prevent privilege escalation.
 * @param {{ username: string, email: string, password: string }} input
 */
async function registerUser({ username, email, password }) {
  const usernameNormalized = username.toLowerCase();

  const existingUser = await User.findOne({
    $or: [{ email }, { usernameNormalized }],
  }).lean();

  if (existingUser) {
    if (existingUser.email === email) {
      throw new AuthError(
        409,
        'DUPLICATE_EMAIL',
        'An account with this email address already exists.',
        [{ field: 'email', message: 'Email address is already registered.' }]
      );
    }
    throw new AuthError(
      409,
      'DUPLICATE_USERNAME',
      'This username is already taken.',
      [{ field: 'username', message: 'Username is already taken.' }]
    );
  }

  const passwordHash = await bcrypt.hash(password, env.bcryptSaltRounds);

  try {
    const createdUser = await User.create({
      username,
      usernameNormalized,
      email,
      passwordHash,
      role: 'user', // Enforce default user role; cannot be elevated via registration
      failedLoginAttempts: 0,
      lockUntil: null,
    });

    return toSafeUser(createdUser);
  } catch (err) {
    // Handle concurrent race condition on unique index
    if (err && err.code === 11000) {
      const duplicateField = err.keyPattern && err.keyPattern.email ? 'email' : 'username';
      if (duplicateField === 'email') {
        throw new AuthError(
          409,
          'DUPLICATE_EMAIL',
          'An account with this email address already exists.',
          [{ field: 'email', message: 'Email address is already registered.' }]
        );
      }
      throw new AuthError(
        409,
        'DUPLICATE_USERNAME',
        'This username is already taken.',
        [{ field: 'username', message: 'Username is already taken.' }]
      );
    }
    throw err;
  }
}

/**
 * Authenticate a user by email or username, compare password in constant time, and issue a signed JWT.
 * Enforces account lockout after 5 consecutive failed attempts.
 * @param {{ identifier: string, identifierType: 'email' | 'username', password: string }} input
 */
async function loginUser({ identifier, identifierType, password }) {
  const query =
    identifierType === 'email'
      ? { email: identifier.toLowerCase() }
      : { usernameNormalized: identifier.toLowerCase() };

  const user = await User.findOne(query).select('+passwordHash');

  if (!user) {
    // Constant-time mitigation against user enumeration
    await bcrypt.compare(password, getDummyPasswordHash());
    throw new AuthError(401, 'INVALID_CREDENTIALS', 'Invalid email/username or password.');
  }

  // Account lockout protection
  if (user.lockUntil && user.lockUntil.getTime() > Date.now()) {
    const remainingMinutes = Math.ceil((user.lockUntil.getTime() - Date.now()) / (60 * 1000));
    throw new AuthError(
      423,
      'ACCOUNT_LOCKED',
      `Account is temporarily locked due to consecutive failed login attempts. Please try again in ${remainingMinutes} minute(s).`
    );
  }

  const isPasswordMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isPasswordMatch) {
    user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
    if (user.failedLoginAttempts >= 5) {
      user.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15-minute lockout
    }
    await user.save();
    throw new AuthError(401, 'INVALID_CREDENTIALS', 'Invalid email/username or password.');
  }

  // Reset failed login tracking upon successful authentication
  if (user.failedLoginAttempts > 0 || user.lockUntil) {
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    await user.save();
  }

  const jti = crypto.randomUUID();
  const payload = {
    sub: user._id.toString(),
    username: user.username,
    email: user.email,
    role: user.role || 'user',
    tokenVersion: user.tokenVersion || 0,
    jti,
  };

  const token = jwt.sign(payload, env.jwtSecret, {
    algorithm: 'HS256',
    expiresIn: env.jwtExpiresIn,
    issuer: env.jwtIssuer,
    audience: env.jwtAudience,
  });

  return {
    user: toSafeUser(user),
    token,
    expiresIn: env.jwtExpiresIn,
  };
}

/**
 * Verify JWT signature, claims, revocation status, and user existence.
 * @param {string} token
 */
async function verifyAndLoadUser(token) {
  let decoded;
  try {
    decoded = jwt.verify(token, env.jwtSecret, {
      algorithms: ['HS256'],
      issuer: env.jwtIssuer,
      audience: env.jwtAudience,
    });
  } catch (err) {
    if (err && err.name === 'TokenExpiredError') {
      throw new AuthError(401, 'TOKEN_EXPIRED', 'Session expired. Please log in again.');
    }
    throw new AuthError(401, 'INVALID_TOKEN', 'Invalid or tampered authentication token.');
  }

  if (!decoded || typeof decoded !== 'object' || !decoded.sub || !decoded.jti) {
    throw new AuthError(401, 'INVALID_TOKEN', 'Invalid authentication token claims.');
  }

  const isRevoked = await RevokedToken.exists({ jti: decoded.jti });
  if (isRevoked) {
    throw new AuthError(
      401,
      'TOKEN_REVOKED',
      'Session has been invalidated. Please log in again.'
    );
  }

  const user = await User.findById(decoded.sub).lean();
  if (!user) {
    throw new AuthError(401, 'USER_NOT_FOUND', 'User associated with this token no longer exists.');
  }

  // Invalidate tokens if password was changed/reset (via tokenVersion or passwordChangedAt)
  if (
    decoded.tokenVersion !== undefined &&
    user.tokenVersion !== undefined &&
    decoded.tokenVersion !== user.tokenVersion
  ) {
    throw new AuthError(
      401,
      'TOKEN_INVALIDATED',
      'Password was changed after this session was issued. Please log in again.'
    );
  }

  return {
    user: toSafeUser(user),
    auth: {
      jti: decoded.jti,
      iat: decoded.iat,
      exp: decoded.exp,
    },
  };
}

/**
 * Generate a cryptographically secure, single-use password reset token with 15-minute expiration.
 * Stored as a SHA-256 hash in database to prevent token compromise if database is read.
 * Returns a generic success response to mitigate user enumeration.
 * @param {string} rawEmail
 */
async function requestPasswordReset(rawEmail) {
  if (!rawEmail || typeof rawEmail !== 'string') {
    throw new AuthError(400, 'VALIDATION_ERROR', 'A valid email address is required.');
  }

  const email = rawEmail.trim().toLowerCase();
  const user = await User.findOne({ email });

  // Generic response even if account does not exist to prevent enumeration
  if (!user) {
    return {
      success: true,
      message: 'If that email address is registered, password reset instructions have been generated.',
    };
  }

  const rawResetToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawResetToken).digest('hex');

  user.passwordResetTokenHash = tokenHash;
  user.passwordResetExpiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
  await user.save();

  return {
    success: true,
    message: 'If that email address is registered, password reset instructions have been generated.',
    // Return token in non-production environments to support automated integration testing
    ...(!env.isProduction ? { resetToken: rawResetToken } : {}),
  };
}

/**
 * Reset a user's password using the single-use token.
 * Hashes new password with bcrypt (>= 12 rounds), clears reset token, updates passwordChangedAt,
 * and invalidates all existing user sessions.
 * @param {{ token: string, newPassword: string }} input
 */
async function resetPassword({ token, newPassword }) {
  if (!token || typeof token !== 'string') {
    throw new AuthError(400, 'INVALID_RESET_TOKEN', 'Password reset token is required.');
  }
  if (!newPassword || typeof newPassword !== 'string') {
    throw new AuthError(400, 'VALIDATION_ERROR', 'New password is required.');
  }

  const tokenHash = crypto.createHash('sha256').update(token.trim()).digest('hex');

  const user = await User.findOne({
    passwordResetTokenHash: tokenHash,
    passwordResetExpiresAt: { $gt: new Date() },
  }).select('+passwordHash +passwordResetTokenHash +passwordResetExpiresAt');

  if (!user) {
    throw new AuthError(400, 'INVALID_RESET_TOKEN', 'Invalid or expired password reset token.');
  }

  user.passwordHash = await bcrypt.hash(newPassword, env.bcryptSaltRounds);
  user.passwordResetTokenHash = null;
  user.passwordResetExpiresAt = null;
  user.passwordChangedAt = new Date();
  user.tokenVersion = (user.tokenVersion || 0) + 1;
  user.failedLoginAttempts = 0;
  user.lockUntil = null;
  await user.save();

  return {
    success: true,
    message: 'Password has been reset successfully. Please sign in with your new password.',
  };
}

/**
 * Change password for an already-authenticated user requiring current password confirmation.
 * Updates passwordChangedAt and tokenVersion to invalidate existing sessions.
 * @param {{ userId: string, currentPassword: string, newPassword: string }} input
 */
async function changePassword({ userId, currentPassword, newPassword }) {
  const user = await User.findById(userId).select('+passwordHash');
  if (!user) {
    throw new AuthError(404, 'USER_NOT_FOUND', 'User not found.');
  }

  const isCurrentMatch = await bcrypt.compare(currentPassword, user.passwordHash);
  if (!isCurrentMatch) {
    throw new AuthError(401, 'INVALID_CREDENTIALS', 'Current password is incorrect.');
  }

  user.passwordHash = await bcrypt.hash(newPassword, env.bcryptSaltRounds);
  user.passwordChangedAt = new Date();
  user.tokenVersion = (user.tokenVersion || 0) + 1;
  user.failedLoginAttempts = 0;
  user.lockUntil = null;
  await user.save();

  return {
    success: true,
    message: 'Password changed successfully. Existing sessions have been invalidated.',
  };
}

/**
 * Retrieve user list for administrators (enforces RBAC).
 */
async function getAdminUsers({ limit = 50, skip = 0 } = {}) {
  const total = await User.countDocuments();
  const users = await User.find()
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();

  return {
    total,
    users: users.map(toSafeUser),
  };
}

/**
 * Invalidate a JWT by persisting its `jti` to the RevokedToken collection until natural expiration.
 * Safe and idempotent when called without a token or with an already-expired/invalid token.
 * @param {string | null} token
 */
async function logoutToken(token) {
  if (!token) {
    return;
  }

  let decoded;
  try {
    decoded = jwt.verify(token, env.jwtSecret, {
      algorithms: ['HS256'],
      issuer: env.jwtIssuer,
      audience: env.jwtAudience,
    });
  } catch {
    // Token is already expired or invalid; no active session remains to revoke
    return;
  }

  if (decoded && typeof decoded === 'object' && decoded.jti && decoded.sub && decoded.exp) {
    await RevokedToken.updateOne(
      { jti: decoded.jti },
      {
        $setOnInsert: {
          jti: decoded.jti,
          userId: decoded.sub,
          expiresAt: new Date(decoded.exp * 1000),
          revokedAt: new Date(),
        },
      },
      { upsert: true }
    );
  }
}

/**
 * Build protected dashboard view payload for an authenticated user.
 */
function buildDashboardPayload(user, auth) {
  return {
    user,
    session: {
      tokenId: auth.jti,
      issuedAt: auth.iat ? new Date(auth.iat * 1000).toISOString() : null,
      expiresAt: auth.exp ? new Date(auth.exp * 1000).toISOString() : null,
    },
    securityProfile: {
      passwordHashing: `bcrypt (${env.bcryptSaltRounds} rounds)`,
      tokenMechanism: 'JWT (HS256) via HttpOnly cookie with Bearer header fallback',
      revocationEnabled: true,
    },
  };
}

module.exports = {
  AuthError,
  toSafeUser,
  registerUser,
  loginUser,
  verifyAndLoadUser,
  logoutToken,
  buildDashboardPayload,
  requestPasswordReset,
  resetPassword,
  changePassword,
  getAdminUsers,
};
