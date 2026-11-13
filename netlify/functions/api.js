const serverless = require('serverless-http');
const app = require('../../backend/src/app');
const { connectDatabase } = require('../../backend/src/config/db');
const { isNetlifyDatabaseActive } = require('../../backend/src/config/netlifyDatabase');

let isConnected = false;
const serverlessHandler = serverless(app);

module.exports.handler = async (event, context) => {
  // Allow callback to return immediately without waiting for open connections
  context.callbackWaitsForEmptyEventLoop = false;

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

  return serverlessHandler(event, context);
};
