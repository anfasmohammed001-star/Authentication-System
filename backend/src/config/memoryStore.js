'use strict';

const fs = require('fs');
const path = require('path');

const TMP_DIR = process.env.TEMP || process.env.TMP || '/tmp';
const USERS_FILE = path.join(TMP_DIR, 'secure_auth_users.json');
const TOKENS_FILE = path.join(TMP_DIR, 'secure_auth_tokens.json');

// In-memory maps
const usersMap = new Map();
const revokedTokensMap = new Map();

// Load persisted state if exists
function loadState() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
      if (Array.isArray(data)) {
        data.forEach((u) => {
          usersMap.set(String(u.id), {
            ...u,
            createdAt: new Date(u.createdAt),
            updatedAt: new Date(u.updatedAt),
            lockUntil: u.lockUntil ? new Date(u.lockUntil) : null,
            passwordResetExpiresAt: u.passwordResetExpiresAt ? new Date(u.passwordResetExpiresAt) : null,
            passwordChangedAt: u.passwordChangedAt ? new Date(u.passwordChangedAt) : null,
          });
        });
      }
    }
  } catch (err) {
    console.warn('[MEMORY STORE] Could not read users file:', err.message);
  }

  try {
    if (fs.existsSync(TOKENS_FILE)) {
      const data = JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8'));
      if (Array.isArray(data)) {
        data.forEach((t) => {
          revokedTokensMap.set(t.jti, { ...t, expiresAt: new Date(t.expiresAt) });
        });
      }
    }
  } catch (err) {
    console.warn('[MEMORY STORE] Could not read tokens file:', err.message);
  }
}

function persistUsers() {
  try {
    const list = Array.from(usersMap.values());
    fs.writeFileSync(USERS_FILE, JSON.stringify(list, null, 2), 'utf8');
  } catch (err) {
    console.warn('[MEMORY STORE] Could not write users file:', err.message);
  }
}

function persistTokens() {
  try {
    const list = Array.from(revokedTokensMap.values());
    fs.writeFileSync(TOKENS_FILE, JSON.stringify(list, null, 2), 'utf8');
  } catch (err) {
    console.warn('[MEMORY STORE] Could not write tokens file:', err.message);
  }
}

loadState();

let idCounter = Date.now();

const memoryUserRepo = {
  async findOne({ email, usernameNormalized, id }) {
    if (id !== undefined) {
      return usersMap.get(String(id)) || null;
    }
    for (const u of usersMap.values()) {
      if (email && u.email.toLowerCase() === email.toLowerCase()) {
        return u;
      }
      if (usernameNormalized && u.usernameNormalized.toLowerCase() === usernameNormalized.toLowerCase()) {
        return u;
      }
    }
    return null;
  },

  async findById(id) {
    return usersMap.get(String(id)) || null;
  },

  async findByResetToken(tokenHash) {
    const now = Date.now();
    for (const u of usersMap.values()) {
      if (
        u.passwordResetTokenHash === tokenHash &&
        u.passwordResetExpiresAt &&
        u.passwordResetExpiresAt.getTime() > now
      ) {
        return u;
      }
    }
    return null;
  },

  async create({ username, usernameNormalized, email, passwordHash, role = 'user' }) {
    const id = String(++idCounter);
    const now = new Date();
    const newUser = {
      id,
      _id: id,
      username,
      usernameNormalized: usernameNormalized || username.toLowerCase(),
      email: email.toLowerCase(),
      passwordHash,
      role,
      failedLoginAttempts: 0,
      lockUntil: null,
      passwordResetTokenHash: null,
      passwordResetExpiresAt: null,
      passwordChangedAt: null,
      tokenVersion: 0,
      createdAt: now,
      updatedAt: now,
    };
    usersMap.set(id, newUser);
    persistUsers();
    return newUser;
  },

  async updateFailedAttempts(userId, attempts, lockUntil) {
    const u = usersMap.get(String(userId));
    if (u) {
      u.failedLoginAttempts = attempts;
      u.lockUntil = lockUntil;
      u.updatedAt = new Date();
      persistUsers();
    }
  },

  async resetFailedAttempts(userId) {
    const u = usersMap.get(String(userId));
    if (u) {
      u.failedLoginAttempts = 0;
      u.lockUntil = null;
      u.updatedAt = new Date();
      persistUsers();
    }
  },

  async setResetToken(userId, tokenHash, expiresAt) {
    const u = usersMap.get(String(userId));
    if (u) {
      u.passwordResetTokenHash = tokenHash;
      u.passwordResetExpiresAt = expiresAt;
      u.updatedAt = new Date();
      persistUsers();
    }
  },

  async resetPassword(userId, passwordHash) {
    const u = usersMap.get(String(userId));
    if (u) {
      u.passwordHash = passwordHash;
      u.passwordResetTokenHash = null;
      u.passwordResetExpiresAt = null;
      u.passwordChangedAt = new Date();
      u.tokenVersion = (u.tokenVersion || 0) + 1;
      u.failedLoginAttempts = 0;
      u.lockUntil = null;
      u.updatedAt = new Date();
      persistUsers();
    }
  },

  async updatePassword(userId, passwordHash) {
    const u = usersMap.get(String(userId));
    if (u) {
      u.passwordHash = passwordHash;
      u.passwordChangedAt = new Date();
      u.tokenVersion = (u.tokenVersion || 0) + 1;
      u.failedLoginAttempts = 0;
      u.lockUntil = null;
      u.updatedAt = new Date();
      persistUsers();
    }
  },

  async count() {
    return usersMap.size;
  },

  async list({ limit = 50, skip = 0 } = {}) {
    const all = Array.from(usersMap.values()).sort((a, b) => b.createdAt - a.createdAt);
    return all.slice(skip, skip + limit).map((u) => ({
      id: u.id,
      username: u.username,
      email: u.email,
      role: u.role,
      createdAt: u.createdAt,
    }));
  },
};

const memoryTokenRepo = {
  async isRevoked(jti) {
    const entry = revokedTokensMap.get(jti);
    if (!entry) return false;
    if (entry.expiresAt && entry.expiresAt.getTime() < Date.now()) {
      revokedTokensMap.delete(jti);
      return false;
    }
    return true;
  },

  async revoke({ jti, userId, expiresAt }) {
    revokedTokensMap.set(jti, { jti, userId: String(userId), expiresAt });
    persistTokens();
  },
};

module.exports = {
  memoryUserRepo,
  memoryTokenRepo,
};
