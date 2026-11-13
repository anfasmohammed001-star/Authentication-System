const express = require('express');
const rateLimit = require('express-rate-limit');
const env = require('../../config/env');
const authController = require('./auth.controller');
const { authenticate, requireRole } = require('./auth.middleware');

const router = express.Router();

const authRateLimiter = rateLimit({
  windowMs: env.rateLimitWindowMs,
  max: env.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    code: 'RATE_LIMIT_EXCEEDED',
    message: 'Too many authentication attempts. Please try again later.',
  },
});

// Public authentication & password recovery endpoints
router.post('/register', authRateLimiter, authController.register);
router.post('/login', authRateLimiter, authController.login);
router.post('/logout', authController.logout);
router.post('/forgot-password', authRateLimiter, authController.forgotPassword);
router.post('/reset-password', authRateLimiter, authController.resetPassword);

// Protected authenticated user endpoints
router.get('/me', authenticate, authController.getMe);
router.post('/change-password', authenticate, authController.changePassword);

// Protected administrative RBAC endpoints (role='admin' required)
router.get('/admin/users', authenticate, requireRole('admin'), authController.getAdminUsers);
router.get('/admin/stats', authenticate, requireRole('admin'), authController.getAdminStats);

module.exports = router;
