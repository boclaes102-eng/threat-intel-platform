import 'dotenv/config';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import path from 'path';
import { buildServer } from './api/server';
import { redis } from './lib/redis';
import { env } from './lib/env';
import { logger } from './lib/logger';

async function main() {
  console.log(`Starting API — PORT=${env.PORT} HOST=${env.HOST} NODE_ENV=${env.NODE_ENV}`);

  console.log('Running migrations...');
  const migrateClient = postgres(env.DATABASE_URL, { max: 1 });
  await migrate(drizzle(migrateClient), { migrationsFolder: path.join(__dirname, 'drizzle') });
  await migrateClient.end({ timeout: 5 });
  console.log('Migrations complete.');
  const server = await buildServer();
  console.log('Server built, binding...');
  await server.listen({ port: env.PORT, host: env.HOST });
  console.log(`Threat Intel API listening on ${env.HOST}:${env.PORT}`);

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutting down...');
    await server.close();
    await redis.quit();
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

process.on('uncaughtException', (err) => {
  console.error('[fatal] uncaughtException:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('[fatal] unhandledRejection:', reason);
  process.exit(1);
});

main().catch((err) => {
  console.error('[fatal] main() crashed:', err);
  process.exit(1);
});
