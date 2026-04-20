import { Worker, type Job } from 'bullmq';
import { eq } from 'drizzle-orm';
import { db } from '../db';
import { assets, vulnerabilities, assetVulnerabilities, alerts, users, logEvents } from '../db/schema';
import { sendAlertEmail } from '../lib/mailer';
import { jobsTotal, jobDuration } from '../lib/metrics';
import { logger } from '../lib/logger';
import { env } from '../lib/env';
import type { AssetScanJobData } from './queues';

// Correlates known CVEs against an asset by matching product keywords in
// the asset value against CVE affected_products CPE strings.
export function createAssetScanWorker() {
  return new Worker<AssetScanJobData>(
    'asset-scan',
    async (job: Job<AssetScanJobData>) => {
      const end = jobDuration.startTimer({ queue: 'asset-scan' });

      try {
        const { assetId, userId } = job.data;

        const asset = await db.query.assets.findFirst({
          where: eq(assets.id, assetId),
        });

        if (!asset) {
          logger.warn({ assetId }, 'Asset not found for scan');
          return;
        }

        const keyword = asset.label ?? asset.value;
        const allVulns = await db.select().from(vulnerabilities);

        let linked = 0;
        for (const vuln of allVulns) {
          const products = (vuln.affectedProducts as string[]) ?? [];
          const matches = products.some(
            (p) => p.toLowerCase().includes(keyword.toLowerCase()),
          );

          if (!matches) continue;

          const existing = await db.query.assetVulnerabilities.findFirst({
            where: (av, { and, eq }) =>
              and(eq(av.assetId, assetId), eq(av.vulnerabilityId, vuln.id)),
          });

          if (!existing) {
            await db.insert(assetVulnerabilities).values({
              assetId,
              vulnerabilityId: vuln.id,
              status: 'open',
            });

            if (vuln.severity === 'critical' || vuln.severity === 'high') {
              const severity = vuln.severity as 'critical' | 'high';
              const title = `New ${severity.toUpperCase()} CVE linked: ${vuln.cveId}`;
              const details = { cveId: vuln.cveId, cvssScore: vuln.cvssScore, severity, description: vuln.description?.slice(0, 200) };

              await db.insert(alerts).values({ userId, assetId, type: 'vulnerability', severity, title, details });

              // Emit SIEM event for correlation
              await db.insert(logEvents).values({
                userId,
                source:   'asset-scanner',
                category: 'threat',
                action:   'vuln_match',
                severity,
                message:  `${vuln.cveId} matched asset ${asset.value}`,
                rawData:  { cveId: vuln.cveId, cvssScore: vuln.cvssScore, assetId },
              });

              const user = await db.query.users.findFirst({ where: eq(users.id, userId), columns: { email: true } });
              if (user) {
                sendAlertEmail({ to: user.email, title, severity, assetValue: asset.value, details }).catch(() => {});
              }
            }

            linked++;
          }
        }

        await db
          .update(assets)
          .set({ lastScanned: new Date() })
          .where(eq(assets.id, assetId));

        logger.info({ assetId, linked }, 'Asset scan complete');
        jobsTotal.inc({ queue: 'asset-scan', status: 'completed' });
      } catch (err) {
        logger.error({ err, jobData: job.data }, 'Asset scan failed');
        jobsTotal.inc({ queue: 'asset-scan', status: 'failed' });
        throw err;
      } finally {
        end();
      }
    },
    { connection: { url: env.REDIS_URL }, concurrency: 3 },
  );
}
