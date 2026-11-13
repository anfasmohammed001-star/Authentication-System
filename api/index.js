'use strict';

const mongoose = require('mongoose');
const app = require('../backend/src/app');
const { connectDatabase } = require('../backend/src/config/db');
const { isNetlifyDatabaseActive } = require('../backend/src/config/netlifyDatabase');

let isConnected = false;

module.exports = async (req, res) => {
  // Normalize req.url so Express routes matching /api/* match correctly
  if (!req.url.startsWith('/api')) {
    req.url = '/api' + (req.url.startsWith('/') ? req.url : '/' + req.url);
  }

  // Health check endpoint can respond without database
  if (req.url === '/api/health' || req.url === '/api/health/') {
    const dbStates = ['disconnected', 'connected', 'connecting', 'disconnecting'];
    const state = isNetlifyDatabaseActive()
      ? 'connected (Netlify DB)'
      : dbStates[mongoose.connection.readyState] || 'unknown';
    return res.status(200).json({
      success: true,
      status: 'ok',
      database: state,
      platform: 'Vercel Serverless',
      timestamp: new Date().toISOString(),
    });
  }

  if (!isConnected) {
    if (isNetlifyDatabaseActive()) {
      isConnected = true;
    } else {
      try {
        await connectDatabase();
        isConnected = true;
      } catch (err) {
        console.warn('[VERCEL DB WARNING]', err.message);
      }
    }
  }

  // If database is not configured in production environment variables, return structured JSON
  if (mongoose.connection.readyState !== 1 && !isNetlifyDatabaseActive()) {
    // Attempt one quick reconnection
    if (process.env.MONGO_URI) {
      try {
        await connectDatabase();
      } catch (e) {
        console.warn('[VERCEL DB RECONNECT FAILED]', e.message);
      }
    }

    if (mongoose.connection.readyState !== 1 && !isNetlifyDatabaseActive()) {
      return res.status(503).json({
        success: false,
        code: 'DATABASE_UNAVAILABLE',
        message: 'Database is not connected. Please configure MONGO_URI or NETLIFY_DB_URL in your hosting platform environment variables.',
      });
    }
  }

  return app(req, res);
};
