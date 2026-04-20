import { Worker, type Job } from 'bullmq';
import { eq, and, isNull, lte } from 'drizzle-orm';
import { db } from '../db';
import { assets, iocRecords, alerts, users, logEvents } from '../db/schema';
import { enrichIoc } from '../services/ioc-enrichment';
import { sendAlertEmail } from '../lib/mailer';
import { jobsTotal, jobDuration } from '../lib/metrics';
import { logger } from '../lib/logger';
import { env } from '../lib/env';
import type { IocScanJobData } from './queues';

export function createIocScanWorker() {
  return new Worker<IocScanJobData>(
    'ioc-scan',
    async (job: Job<IocScanJobData>) => {
      const end = jobDuration.startTimer({ queue: 'ioc-scan' });

      try {
        // When called with no data, scan all active assets
        if (!job.data.assetId) {
          await scanAllAssets();
        } else {
          await scanSingleAsset(job.data.assetId, job.data.indicator, job.data.userId);
        }
        jobsTotal.inc({ queue: 'ioc-scan', status: 'completed' });
      } catch (err) {
        logger.error({ err, jobData: job.data }, 'IOC scan failed');
        jobsTotal.inc({ queue: 'ioc-scan', status: 'failed' });
        throw err;
      } finally {
        end();
      }
    },
    { connection: { url: env.REDIS_URL }, concurrency: 5 },
  );
}

async function scanAllAssets() {
  const activeAssets = await db
    .select()
    .from(assets)
    .where(and(eq(assets.active, true)));

  logger.info({ count: activeAssets.length }, 'IOC scan: scanning all assets');

  for (const asset of activeAssets) {
    if (asset.type === 'ip' || asset.type === 'domain') {
      await scanSingleAsset(asset.id, asset.value, asset.userId);
    }
  }
}

async function scanSingleAsset(assetId: string, indicator: string, userId: string) {
  const result = await enrichIoc(indicator);

  const expiresAt = new Date(Date.now() + env.IOC_CACHE_TTL * 1000);

  await db
    .insert(iocRecords)
    .values({
      indicator,
      type: result.type,
      verdict: result.verdict,
      score: result.score,
      sources: result.sources,
      lastChecked: new Date(),
      expiresAt,
    })
    .onConflictDoUpdate({
      target: iocRecords.indicator,
      set: {
        verdict: result.verdict,
        score: result.score,
        sources: result.sources,
        lastChecked: new Date(),
        expiresAt,
      },
    });

  if (result.verdict === 'malicious' || result.verdict === 'suspicious') {
    const severity = result.verdict === 'malicious' ? 'high' : 'medium';
    const title = `IOC match: ${indicator}`;

    await db.insert(alerts).values({
      userId,
      assetId,
      type: 'ioc_match',
      severity,
      title,
      details: { indicator, verdict: result.verdict, score: result.score, sources: result.sources },
    });

    // Emit SIEM event for correlation
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(indicator);
    await db.insert(logEvents).values({
      userId,
      source:   'ioc-scanner',
      category: 'threat',
      action:   'ioc_match',
      severity,
      sourceIp: isIp ? indicator : undefined,
      message:  `IOC match: ${indicator} — ${result.verdict} (score: ${result.score})`,
      rawData:  { indicator, verdict: result.verdict, score: result.score },
    });

    // Send email notification (fire-and-forget, no-op if SMTP not configured)
    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
      columns: { email: true },
    });
    if (user) {
      sendAlertEmail({ to: user.email, title, severity, assetValue: indicator, details: { verdict: result.verdict, score: result.score } }).catch(() => {});
    }

    logger.warn({ indicator, verdict: result.verdict, score: result.score }, 'IOC threat detected');
  }

  await db
    .update(assets)
    .set({ lastScanned: new Date() })
    .where(eq(assets.id, assetId));
}
