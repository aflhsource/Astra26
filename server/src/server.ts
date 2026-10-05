import http from 'node:http';
import { createApp } from './app.js';
import { env } from './config/env.js';
import { connectDatabase, disconnectDatabase } from './database/connection.js';

const app = createApp();
const server = http.createServer(app);

async function start(): Promise<void> {
  await connectDatabase(env.MONGODB_URI);
  server.listen(env.PORT, () => {
    console.log(JSON.stringify({ level: 'info', event: 'server_started', port: env.PORT }));
  });
}

async function shutdown(signal: string): Promise<void> {
  console.log(JSON.stringify({ level: 'info', event: 'server_shutdown', signal }));
  server.close(async () => {
    await disconnectDatabase();
    process.exit(0);
  });
}

process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));

start().catch((error: unknown) => {
  console.error(JSON.stringify({ level: 'error', event: 'startup_failed', error: String(error) }));
  process.exitCode = 1;
});
