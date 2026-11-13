'use strict';

const serverless = require('serverless-http');
const app = require('../../backend/src/app');
const { connectDatabase } = require('../../backend/src/config/db');
const { isNetlifyDatabaseActive } = require('../../backend/src/config/netlifyDatabase');

let isConnected = false;
const serverlessHandler = serverless(app);

module.exports.handler = async (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;

  // Connect to external DB if configured, otherwise auth service automatically uses embedded zero-config store
  if (!isConnected) {
    if (isNetlifyDatabaseActive()) {
      isConnected = true;
    } else if (process.env.MONGO_URI) {
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
