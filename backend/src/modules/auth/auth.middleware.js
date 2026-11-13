const env = require('../../config/env');
const authService = require('./auth.service');

/**
 * Extract JWT from HttpOnly cookie (primary) or Authorization: Bearer header (fallback).
 * @param {import('express').Request} req
 * @returns {string | null}
 */
function extractTokenFromRequest(req) {
  if (req.cookies && typeof req.cookies[env.cookieName] === 'string') {
    const cookieToken = req.cookies[env.cookieName].trim();
    if (cookieToken) {
      return cookieToken;
    }
  }

  const authHeader = req.headers && req.headers.authorization;
  if (typeof authHeader === 'string') {
    const parts = authHeader.trim().split(/\s+/);
    if (parts.length === 2 && parts[0].toLowerCase() === 'bearer' && parts[1]) {
      return parts[1];
    }
  }

  return null;
}

/**
 * Reusable cookie options ensuring consistency between setCookie and clearCookie.
 */
function getAuthCookieOptions() {
  return {
    httpOnly: true,
    sameSite: env.cookieSameSite,
    secure: env.cookieSecure,
    path: '/',
  };
}

/**
 * API route protection middleware.
 * Rejects missing, tampered, expired, or revoked tokens with 401 Unauthorized.
 */
async function authenticate(req, res, next) {
  try {
    const token = extractTokenFromRequest(req);
    if (!token) {
      return res.status(401).json({
        success: false,
        code: 'MISSING_TOKEN',
        message: 'Authentication required. Please log in.',
      });
    }

    const { user, auth } = await authService.verifyAndLoadUser(token);
    req.user = user;
    req.auth = { ...auth, token };
    return next();
  } catch (err) {
    if (err instanceof authService.AuthError) {
      return res.status(err.statusCode).json({
        success: false,
        code: err.code,
        message: err.message,
      });
    }
    return next(err);
  }
}

/**
 * Frontend HTML page protection middleware (e.g., GET /dashboard).
 * Redirects unauthenticated browser requests to login page; returns 401 for non-HTML clients.
 */
async function protectPage(req, res, next) {
  try {
    const token = extractTokenFromRequest(req);
    if (!token) {
      if (req.accepts('html')) {
        return res.redirect(302, '/?reason=auth_required');
      }
      return res.status(401).json({
        success: false,
        code: 'MISSING_TOKEN',
        message: 'Authentication required.',
      });
    }

    const { user, auth } = await authService.verifyAndLoadUser(token);
    req.user = user;
    req.auth = { ...auth, token };

    // Prevent browser back-button caching of protected pages after logout
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    return next();
  } catch (err) {
    res.clearCookie(env.cookieName, getAuthCookieOptions());
    if (req.accepts('html')) {
      return res.redirect(302, '/?reason=session_expired');
    }
    if (err instanceof authService.AuthError) {
      return res.status(err.statusCode).json({
        success: false,
        code: err.code,
        message: err.message,
      });
    }
    return res.status(401).json({
      success: false,
      code: 'UNAUTHORIZED',
      message: 'Authentication required.',
    });
  }
}

/**
 * Role-Based Access Control (RBAC) middleware.
 * Verifies that the authenticated user possesses one of the allowed roles.
 * Never trusts frontend-supplied role parameters; strictly validates the authenticated session.
 * @param  {...string} allowedRoles
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        message: 'Authentication required. Please sign in.',
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        message: 'Access denied: insufficient permissions to access this resource.',
      });
    }

    return next();
  };
}

module.exports = {
  extractTokenFromRequest,
  getAuthCookieOptions,
  authenticate,
  protectPage,
  requireRole,
};
