const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');

const env = require('./config/env');
const authRoutes = require('./modules/auth/auth.routes');
const authController = require('./modules/auth/auth.controller');
const { authenticate, protectPage } = require('./modules/auth/auth.middleware');
const { sanitizeRequestMiddleware } = require('./modules/auth/auth.validation');

const app = express();

// Trust first proxy if behind reverse proxy in production
if (env.isProduction) {
  app.set('trust proxy', 1);
}

// Security headers with Content Security Policy supporting local frontend and React/Tailwind CDN
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "'unsafe-eval'",
          'https://cdn.tailwindcss.com',
          'https://unpkg.com',
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://cdn.tailwindcss.com',
          'https://fonts.googleapis.com',
        ],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// CORS configuration allowing credentials for HttpOnly cookies
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || env.corsOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Origin not allowed by CORS policy.'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// Request body parsing with strict size limit & cookie parsing
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(cookieParser());

// NoSQL operator & prototype pollution sanitization
app.use(sanitizeRequestMiddleware);

// API health check
app.get(['/api/health', '/.netlify/functions/api/health'], (_req, res) => {
  const dbStates = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  const state = dbStates[mongoose.connection.readyState] || 'unknown';
  res.status(200).json({
    success: true,
    status: 'ok',
    database: state,
    timestamp: new Date().toISOString(),
  });
});

// Dedicated Auth Module & Protected Dashboard API (supports direct & Netlify function paths)
app.use(['/api/auth', '/.netlify/functions/api/auth'], authRoutes);
app.get(
  ['/api/dashboard', '/.netlify/functions/api/dashboard'],
  authenticate,
  authController.getDashboard
);

// Frontend static pages with server-side route guard for /dashboard
const frontendDir = path.resolve(__dirname, '../../frontend');

app.get(['/dashboard', '/dashboard.html'], protectPage, (_req, res) => {
  return res.sendFile(path.join(frontendDir, 'dashboard.html'));
});

app.get(['/', '/login', '/index.html'], (_req, res) => {
  return res.sendFile(path.join(frontendDir, 'index.html'));
});

app.get(['/register', '/register.html'], (_req, res) => {
  return res.sendFile(path.join(frontendDir, 'register.html'));
});

app.use(express.static(frontendDir, { index: false }));

// 404 handler for unmatched API routes
app.use(['/api', '/.netlify/functions/api'], (_req, res) => {
  res.status(404).json({
    success: false,
    code: 'NOT_FOUND',
    message: 'API endpoint not found.',
  });
});

// Fallback for unknown frontend routes
app.use((_req, res) => {
  res.status(404).sendFile(path.join(frontendDir, 'index.html'));
});

// Centralized error handler (never expose sensitive details or stack traces in production)
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({
      success: false,
      code: 'INVALID_JSON',
      message: 'Malformed JSON request body.',
    });
  }

  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({
      success: false,
      code: 'PAYLOAD_TOO_LARGE',
      message: 'Request payload exceeds the maximum allowed size.',
    });
  }

  if (err && err.message === 'Origin not allowed by CORS policy.') {
    return res.status(403).json({
      success: false,
      code: 'CORS_FORBIDDEN',
      message: 'Cross-origin request denied.',
    });
  }

  if (!env.isTest) {
    console.error('[ERROR]', err && err.message ? err.message : 'Unexpected server error');
  }

  return res.status(500).json({
    success: false,
    code: 'INTERNAL_SERVER_ERROR',
    message: 'An unexpected internal error occurred.',
  });
});

module.exports = app;

