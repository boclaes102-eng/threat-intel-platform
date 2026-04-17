import 'dotenv/config';
import { buildServer } from './api/server';
import { redis } from './lib/redis';
import { env } from './lib/env';
import { logger } from './lib/logger';

async function main() {
  const server = await buildServer();

  await server.listen({ port: env.PORT, host: env.HOST });
  logger.info(`Threat Intel API listening on ${env.HOST}:${env.PORT}`);

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutting down...');
    await server.close();
    await redis.quit();
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  logger.error(err, 'Fatal startup error');
  process.exit(1);
});
