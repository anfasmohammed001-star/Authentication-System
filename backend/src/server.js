const env = require('./config/env');
const { connectDatabase, disconnectDatabase } = require('./config/db');
const app = require('./app');

let server = null;

async function startServer() {
  try {
    await connectDatabase();

    server = app.listen(env.port, () => {
      console.log(
        `[SERVER] Auth System running in ${env.nodeEnv} mode at http://localhost:${env.port}`
      );
    });

    return server;
  } catch (err) {
    console.error('[STARTUP ERROR] Failed to start server:', err.message);
    process.exit(1);
  }
}

async function shutdown(signal) {
  console.log(`\n[SERVER] Received ${signal}. Shutting down gracefully...`);
  if (server) {
    server.close(async () => {
      await disconnectDatabase();
      process.exit(0);
    });
  } else {
    await disconnectDatabase();
    process.exit(0);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

if (require.main === module) {
  startServer();
}

module.exports = { startServer, shutdown };

