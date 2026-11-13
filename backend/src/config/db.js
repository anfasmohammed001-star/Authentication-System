const mongoose = require('mongoose');
const env = require('./env');

// Enforce strict query filtering and filter sanitization to prevent NoSQL operator injection
mongoose.set('strictQuery', true);
mongoose.set('sanitizeFilter', true);

let memoryServerInstance = null;

/**
 * Connect Mongoose to the configured MongoDB URI (or ephemeral in-memory MongoDB in dev/test if enabled).
 * @param {string} [overrideUri]
 * @returns {Promise<mongoose.Connection>}
 */
async function connectDatabase(overrideUri) {
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  let targetUri = overrideUri || env.mongoUri;

  if (!overrideUri && env.useInMemoryDb) {
    try {
      // Lazy load devDependency only when explicitly enabled outside production
      const { MongoMemoryServer } = require('mongodb-memory-server');
      memoryServerInstance = await MongoMemoryServer.create();
      targetUri = memoryServerInstance.getUri();
      if (!env.isTest) {
        console.log('[DB] Started ephemeral in-memory MongoDB instance (USE_IN_MEMORY_DB=true).');
      }
    } catch (memErr) {
      console.warn('[DB] in-memory MongoDB initialization skipped:', memErr.message);
    }
  }

  await mongoose.connect(targetUri, {
    serverSelectionTimeoutMS: 5000,
    autoIndex: true,
  });

  if (!env.isTest) {
    console.log('[DB] Connected to MongoDB successfully.');
  }

  return mongoose.connection;
}

/**
 * Gracefully close Mongoose connection and stop any ephemeral in-memory MongoDB server.
 */
async function disconnectDatabase() {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }
  if (memoryServerInstance) {
    await memoryServerInstance.stop();
    memoryServerInstance = null;
  }
}

module.exports = {
  connectDatabase,
  disconnectDatabase,
};

