const mongoose = require('mongoose');
const serverless = require('serverless-http');
const app = require('../../backend/src/app');
const { connectDatabase } = require('../../backend/src/config/db');
const { isNetlifyDatabaseActive } = require('../../backend/src/config/netlifyDatabase');

let isConnected = false;
const serverlessHandler = serverless(app);

module.exports.handler = async (event, context) => {
  // Allow callback to return immediately without waiting for open connections
  context.callbackWaitsForEmptyEventLoop = false;

  // Handle health check without waiting for database
  if (event.path && (event.path.endsWith('/health') || event.path.endsWith('/health/'))) {
    const dbStates = ['disconnected', 'connected', 'connecting', 'disconnecting'];
    const state = isNetlifyDatabaseActive()
      ? 'connected (Netlify DB)'
      : dbStates[mongoose.connection.readyState] || 'unknown';
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        success: true,
        status: 'ok',
        database: state,
        platform: 'Netlify Serverless Functions',
        timestamp: new Date().toISOString(),
      }),
    };
  }

  if (!isConnected) {
    if (isNetlifyDatabaseActive()) {
      console.log('[NETLIFY FUNCTION] Connected via @netlify/database managed Postgres.');
      isConnected = true;
    } else {
      try {
        await connectDatabase();
        isConnected = true;
      } catch (err) {
        console.warn('[NETLIFY FUNCTION DB WARNING]', err.message);
      }
    }
  }

  // Gracefully handle unconfigured database in production serverless
  if (mongoose.connection.readyState !== 1 && !isNetlifyDatabaseActive()) {
    if (process.env.MONGO_URI) {
      try {
        await connectDatabase();
      } catch (e) {
        console.warn('[NETLIFY FUNCTION DB RECONNECT FAILED]', e.message);
      }
    }

    if (mongoose.connection.readyState !== 1 && !isNetlifyDatabaseActive()) {
      return {
        statusCode: 503,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          success: false,
          code: 'DATABASE_UNAVAILABLE',
          message: 'Database is not connected. Please configure MONGO_URI or NETLIFY_DB_URL in Netlify site environment variables.',
        }),
      };
    }
  }

  return serverlessHandler(event, context);
};
