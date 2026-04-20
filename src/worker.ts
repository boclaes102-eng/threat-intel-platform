import 'dotenv/config';
import { sql } from 'drizzle-orm';
import { redis } from './lib/redis';
import { logger } from './lib/logger';
import { cveFeedQueue, scheduleRecurringJobs } from './workers/queues';
import { createCveFeedWorker } from './workers/cve-feed-worker';
import { createIocScanWorker } from './workers/ioc-scan-worker';
import { createAssetScanWorker } from './workers/asset-scan-worker';
import { createEventCorrelationWorker } from './workers/event-correlation-worker';
import { db } from './db';
import { vulnerabilities } from './db/schema';

async function main() {
  await redis.connect();

  const workers = [
    createCveFeedWorker(),
    createIocScanWorker(),
    createAssetScanWorker(),
    createEventCorrelationWorker(),
  ];

  logger.info(`Started ${workers.length} BullMQ workers`);

  await scheduleRecurringJobs();
  logger.info('Recurring jobs scheduled (CVE feed: every 6h, IOC scan: every 1h, correlation: every 60s)');

  // If the CVE database is thin (< 500 rows), do a 90-day bulk import
  // then re-scan all assets after 15 min so they correlate against the fresh data
  const [{ count }] = await db.select({ count: sql<number>`count(*)::int` }).from(vulnerabilities);
  if (count < 500) {
    logger.info({ count }, 'CVE database is thin — queuing 90-day bulk import');
    await cveFeedQueue.add('bulk-import', { daysBack: 90 });
  }

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
