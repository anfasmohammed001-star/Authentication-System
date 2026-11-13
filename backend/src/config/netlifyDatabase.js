'use strict';

const { getDatabase, getConnectionString } = require('@netlify/database');

let cachedDb = null;

/**
 * Determine if Netlify Database is configured and active in the current runtime environment.
 * @returns {boolean}
 */
function isNetlifyDatabaseActive() {
  if (process.env.USE_NETLIFY_DB === 'true' || process.env.NETLIFY_DB_URL) {
    return true;
  }
  try {
    const connStr = getConnectionString();
    return Boolean(connStr);
  } catch {
    return false;
  }
}

/**
 * Retrieve the singleton Netlify Database client with auto-selected connection for the environment.
 */
function getNetlifyDb() {
  if (!cachedDb) {
    cachedDb = getDatabase();
  }
  return cachedDb;
}

/**
 * Transform a database row into a standardized user object matching application contracts.
 */
function formatPgUser(row) {
  if (!row) return null;
  return {
    id: String(row.id),
    _id: String(row.id),
    username: row.username,
    usernameNormalized: row.username_normalized,
    email: row.email,
    passwordHash: row.password_hash,
    role: row.role || 'user',
    failedLoginAttempts: row.failed_login_attempts || 0,
    lockUntil: row.lock_until ? new Date(row.lock_until) : null,
    passwordResetTokenHash: row.password_reset_token_hash || null,
    passwordResetExpiresAt: row.password_reset_expires_at ? new Date(row.password_reset_expires_at) : null,
    passwordChangedAt: row.password_changed_at ? new Date(row.password_changed_at) : null,
    tokenVersion: row.token_version || 0,
    createdAt: row.created_at ? new Date(row.created_at) : new Date(),
    updatedAt: row.updated_at ? new Date(row.updated_at) : new Date(),
  };
}

/**
 * Netlify Database repository implementing user storage and query operations with safe SQL templates.
 */
const netlifyUserRepo = {
  async findOne({ email, usernameNormalized, id }) {
    const db = getNetlifyDb();
    if (id !== undefined) {
      const rows = await db.sql`SELECT * FROM users WHERE id = ${Number(id)} LIMIT 1`;
      return formatPgUser(rows[0]);
    }
    if (email && usernameNormalized) {
      const rows = await db.sql`
        SELECT * FROM users
        WHERE email = ${email.toLowerCase()} OR username_normalized = ${usernameNormalized.toLowerCase()}
        LIMIT 1
      `;
      return formatPgUser(rows[0]);
    }
    if (email) {
      const rows = await db.sql`SELECT * FROM users WHERE email = ${email.toLowerCase()} LIMIT 1`;
      return formatPgUser(rows[0]);
    }
    if (usernameNormalized) {
      const rows = await db.sql`SELECT * FROM users WHERE username_normalized = ${usernameNormalized.toLowerCase()} LIMIT 1`;
      return formatPgUser(rows[0]);
    }
    return null;
  },

  async findById(id) {
    const db = getNetlifyDb();
    const rows = await db.sql`SELECT * FROM users WHERE id = ${Number(id)} LIMIT 1`;
    return formatPgUser(rows[0]);
  },

  async findByResetToken(tokenHash) {
    const db = getNetlifyDb();
    const rows = await db.sql`
      SELECT * FROM users
      WHERE password_reset_token_hash = ${tokenHash}
        AND password_reset_expires_at > NOW()
      LIMIT 1
    `;
    return formatPgUser(rows[0]);
  },

  async create({ username, usernameNormalized, email, passwordHash, role = 'user' }) {
    const db = getNetlifyDb();
    const rows = await db.sql`
      INSERT INTO users (username, username_normalized, email, password_hash, role)
      VALUES (${username}, ${usernameNormalized}, ${email}, ${passwordHash}, ${role})
      RETURNING *
    `;
    return formatPgUser(rows[0]);
  },

  async updateFailedAttempts(userId, attempts, lockUntil) {
    const db = getNetlifyDb();
    await db.sql`
      UPDATE users
      SET failed_login_attempts = ${attempts},
          lock_until = ${lockUntil},
          updated_at = NOW()
      WHERE id = ${Number(userId)}
    `;
  },

  async resetFailedAttempts(userId) {
    const db = getNetlifyDb();
    await db.sql`
      UPDATE users
      SET failed_login_attempts = 0,
          lock_until = NULL,
          updated_at = NOW()
      WHERE id = ${Number(userId)}
    `;
  },

  async setResetToken(userId, tokenHash, expiresAt) {
    const db = getNetlifyDb();
    await db.sql`
      UPDATE users
      SET password_reset_token_hash = ${tokenHash},
          password_reset_expires_at = ${expiresAt},
          updated_at = NOW()
      WHERE id = ${Number(userId)}
    `;
  },

  async resetPassword(userId, passwordHash) {
    const db = getNetlifyDb();
    await db.sql`
      UPDATE users
      SET password_hash = ${passwordHash},
          password_reset_token_hash = NULL,
          password_reset_expires_at = NULL,
          password_changed_at = NOW(),
          token_version = token_version + 1,
          failed_login_attempts = 0,
          lock_until = NULL,
          updated_at = NOW()
      WHERE id = ${Number(userId)}
    `;
  },

  async updatePassword(userId, passwordHash) {
    const db = getNetlifyDb();
    await db.sql`
      UPDATE users
      SET password_hash = ${passwordHash},
          password_changed_at = NOW(),
          token_version = token_version + 1,
          failed_login_attempts = 0,
          lock_until = NULL,
          updated_at = NOW()
      WHERE id = ${Number(userId)}
    `;
  },

  async count() {
    const db = getNetlifyDb();
    const rows = await db.sql`SELECT COUNT(*)::int AS count FROM users`;
    return rows[0] ? rows[0].count : 0;
  },

  async list({ limit = 50, skip = 0 } = {}) {
    const db = getNetlifyDb();
    const rows = await db.sql`
      SELECT id, username, email, role, created_at
      FROM users
      ORDER BY created_at DESC
      LIMIT ${limit} OFFSET ${skip}
    `;
    return rows.map((r) => ({
      id: String(r.id),
      username: r.username,
      email: r.email,
      role: r.role,
      createdAt: r.created_at,
    }));
  },
};

/**
 * Netlify Database repository for revoked token tracking on logout.
 */
const netlifyTokenRepo = {
  async isRevoked(jti) {
    const db = getNetlifyDb();
    const rows = await db.sql`SELECT 1 FROM revoked_tokens WHERE jti = ${jti} LIMIT 1`;
    return rows.length > 0;
  },

  async revoke({ jti, userId, expiresAt }) {
    const db = getNetlifyDb();
    await db.sql`
      INSERT INTO revoked_tokens (jti, user_id, expires_at)
      VALUES (${jti}, ${String(userId)}, ${expiresAt})
      ON CONFLICT (jti) DO NOTHING
    `;
  },
};

module.exports = {
  isNetlifyDatabaseActive,
  getNetlifyDb,
  netlifyUserRepo,
  netlifyTokenRepo,
};

