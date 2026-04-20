import { Queue } from 'bullmq';
import Redis from 'ioredis';
import { env } from '../lib/env';

const connection = new Redis(env.REDIS_URL, {
  maxRetriesPerRequest: null,
  enableOfflineQueue: true,
  lazyConnect: true,
});

export const cveFeedQueue          = new Queue('cve-feed',          { connection });
export const iocScanQueue          = new Queue('ioc-scan',          { connection });
export const assetScanQueue        = new Queue('asset-scan',        { connection });
export const eventCorrelationQueue = new Queue('event-correlation', { connection });

export interface CveFeedJobData {
  daysBack?: number;
}

export interface IocScanJobData {
  assetId: string;
  indicator: string;
  userId: string;
}

export interface AssetScanJobData {
  assetId: string;
  userId: string;
}

export async function scheduleRecurringJobs() {
  await cveFeedQueue.add('sync', { daysBack: 1 } satisfies CveFeedJobData, {
    repeat: { pattern: '0 */6 * * *' },
    jobId: 'cve-feed-recurring',
  });

  await iocScanQueue.add('scan-all-assets', {}, {
    repeat: { pattern: '0 * * * *' },
    jobId: 'ioc-scan-recurring',
  });

  await eventCorrelationQueue.add('correlate', {}, {
    repeat: { every: 60_000 },
    jobId: 'event-correlation-recurring',
  });
}
