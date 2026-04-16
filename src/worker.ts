import 'dotenv/config';
import { redis } from './lib/redis';
import { logger } from './lib/logger';
import { scheduleRecurringJobs } from './workers/queues';
import { createCveFeedWorker } from './workers/cve-feed-worker';
import { createIocScanWorker } from './workers/ioc-scan-worker';
import { createAssetScanWorker } from './workers/asset-scan-worker';

async function main() {
  await redis.connect();

  const workers = [
    createCveFeedWorker(),
    createIocScanWorker(),
    createAssetScanWorker(),
  ];

  logger.info(`Started ${workers.length} BullMQ workers`);

  await scheduleRecurringJobs();
  logger.info('Recurring jobs scheduled (CVE feed: every 6h, IOC scan: every 1h)');

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutting down workers...');
    await Promise.all(workers.map((w) => w.close()));
    await redis.quit();
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  logger.error(err, 'Fatal worker error');
  process.exit(1);
});
