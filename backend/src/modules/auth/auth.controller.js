const env = require('../../config/env');
const authService = require('./auth.service');
const {
  validateRegistrationInput,
  validateLoginInput,
  validateForgotPasswordInput,
  validateResetPasswordInput,
  validateChangePasswordInput,
} = require('./auth.validation');
const {
  extractTokenFromRequest,
  getAuthCookieOptions,
} = require('./auth.middleware');

/**
 * POST /api/auth/register
 */
async function register(req, res, next) {
  try {
    const { isValid, errors, sanitized } = validateRegistrationInput(req.body);
    if (!isValid) {
      return res.status(400).json({
        success: false,
        code: 'VALIDATION_ERROR',
        message: errors[0]?.message || 'Validation failed.',
        errors,
      });
    }

    const user = await authService.registerUser(sanitized);

    return res.status(201).json({
      success: true,
      message: 'User registered successfully.',
      data: { user },
    });
  } catch (err) {
    if (err instanceof authService.AuthError) {
      return res.status(err.statusCode).json({
        success: false,
        code: err.code,
        message: err.message,
        ...(err.errors && err.errors.length > 0 ? { errors: err.errors } : {}),
      });
    }
    return next(err);
  }
}

/**
 * POST /api/auth/login
 */
async function login(req, res, next) {
  try {
    const { isValid, errors, sanitized } = validateLoginInput(req.body);
    if (!isValid) {
      return res.status(400).json({
        success: false,
        code: 'VALIDATION_ERROR',
        message: errors[0]?.message || 'Invalid login input.',
        errors,
      });
    }

    const { user, token, expiresIn } = await authService.loginUser(sanitized);

    res.cookie(env.cookieName, token, {
      ...getAuthCookieOptions(),
      maxAge: env.cookieMaxAgeMs,
    });

    return res.status(200).json({
      success: true,
      message: 'Login successful.',
      data: {
        user,
        token,
        expiresIn,
      },
    });
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
 * POST /api/auth/logout
 */
async function logout(req, res, next) {
  try {
    const token = extractTokenFromRequest(req);
    await authService.logoutToken(token);

    res.clearCookie(env.cookieName, getAuthCookieOptions());

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully.',
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * GET /api/auth/me (Protected)
 */
function getMe(req, res) {
  return res.status(200).json({
    success: true,
    data: {
      user: req.user,
      session: {
        expiresAt: req.auth?.exp ? new Date(req.auth.exp * 1000).toISOString() : null,
      },
    },
  });
}

/**
 * GET /api/dashboard (Protected)
 */
function getDashboard(req, res) {
  const dashboardData = authService.buildDashboardPayload(req.user, req.auth);
  return res.status(200).json({
    success: true,
    data: dashboardData,
  });
}

/**
 * POST /api/auth/forgot-password (Rate limited)
 * Generates cryptographically secure, single-use reset token valid for 15 minutes.
 */
async function forgotPassword(req, res, next) {
  try {
    const { isValid, errors, sanitized } = validateForgotPasswordInput(req.body);
    if (!isValid) {
      return res.status(400).json({
        success: false,
        code: 'VALIDATION_ERROR',
        message: errors[0]?.message || 'Invalid email address.',
        errors,
      });
    }

    const result = await authService.requestPasswordReset(sanitized.email);
    return res.status(200).json(result);
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
 * POST /api/auth/reset-password (Rate limited)
 * Resets user password, clears token, and revokes all active sessions.
 */
async function resetPassword(req, res, next) {
  try {
    const { isValid, errors, sanitized } = validateResetPasswordInput(req.body);
    if (!isValid) {
      return res.status(400).json({
        success: false,
        code: 'VALIDATION_ERROR',
        message: errors[0]?.message || 'Invalid password reset input.',
        errors,
      });
    }

    const result = await authService.resetPassword(sanitized);
    return res.status(200).json(result);
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
 * POST /api/auth/change-password (Protected)
 * Allows authenticated users to change password with current password verification.
 */
async function changePassword(req, res, next) {
  try {
    const { isValid, errors, sanitized } = validateChangePasswordInput(req.body);
    if (!isValid) {
      return res.status(400).json({
        success: false,
        code: 'VALIDATION_ERROR',
        message: errors[0]?.message || 'Invalid change password input.',
        errors,
      });
    }

    const result = await authService.changePassword({
      userId: req.user.id,
      currentPassword: sanitized.currentPassword,
      newPassword: sanitized.newPassword,
    });

    // Invalidate current cookie after password change
    res.clearCookie(env.cookieName, getAuthCookieOptions());

    return res.status(200).json(result);
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
 * GET /api/auth/admin/users (Protected, Admin only)
 * Backend-enforced RBAC endpoint returning sanitized user list.
 */
async function getAdminUsers(req, res, next) {
  try {
    const data = await authService.getAdminUsers();
    return res.status(200).json({
      success: true,
      data,
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * GET /api/auth/admin/stats (Protected, Admin only)
 * Backend-enforced RBAC endpoint returning system security telemetry.
 */
function getAdminStats(req, res) {
  return res.status(200).json({
    success: true,
    data: {
      serverTime: new Date().toISOString(),
      nodeEnv: env.nodeEnv,
      bcryptRounds: env.bcryptSaltRounds,
      jwtExpiresIn: env.jwtExpiresIn,
      cookieSameSite: env.cookieSameSite,
      cookieSecure: env.cookieSecure,
      rbacEnforced: true,
      accountLockoutEnforced: true,
    },
  });
}

module.exports = {
  register,
  login,
  logout,
  getMe,
  getDashboard,
  forgotPassword,
  resetPassword,
  changePassword,
  getAdminUsers,
  getAdminStats,
};
