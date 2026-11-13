'use strict';

const app = require('../backend/src/app');
const { connectDatabase } = require('../backend/src/config/db');
const { isNetlifyDatabaseActive } = require('../backend/src/config/netlifyDatabase');

let isConnected = false;

module.exports = async (req, res) => {
  // Normalize req.url so Express routes matching /api/* match correctly
  if (!req.url.startsWith('/api')) {
    req.url = '/api' + (req.url.startsWith('/') ? req.url : '/' + req.url);
  }

  // Connect to external DB if configured, otherwise auth service automatically uses embedded zero-config store
  if (!isConnected) {
    if (isNetlifyDatabaseActive()) {
      isConnected = true;
    } else if (process.env.MONGO_URI) {
      try {
        await connectDatabase();
        isConnected = true;
      } catch (err) {
        console.warn('[VERCEL DB WARNING]', err.message);
      }
    }
  }

  return app(req, res);
};
