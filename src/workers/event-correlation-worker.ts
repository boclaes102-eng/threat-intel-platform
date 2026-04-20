import { Worker, type Job } from 'bullmq';
import { eq, and, gte, isNotNull, isNull, or, sql } from 'drizzle-orm';
import { db } from '../db';
import { logEvents, incidents } from '../db/schema';
import { jobsTotal, jobDuration } from '../lib/metrics';
import { logger } from '../lib/logger';
import { env } from '../lib/env';

// ── Helpers ────────────────────────────────────────────────────────────────

function windowStart(seconds: number): Date {
  return new Date(Date.now() - seconds * 1000);
}

async function upsertIncident(
  userId: string | null,
  ruleName: string,
  title: string,
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
  windowSeconds: number,
  firstSeen: Date,
) {
  // Find an open/investigating incident for this rule that is still within 2x the window
  const userCondition = userId ? eq(incidents.userId, userId) : isNull(incidents.userId);
  const existing = await db.query.incidents.findFirst({
    where: and(
      userCondition,
      eq(incidents.ruleName, ruleName),
      gte(incidents.lastSeenAt, windowStart(windowSeconds * 2)),
    ),
  });

  if (existing && existing.status !== 'resolved') {
    await db
      .update(incidents)
      .set({
        eventCount: existing.eventCount + 1,
        lastSeenAt: new Date(),
        updatedAt:  new Date(),
      })
      .where(eq(incidents.id, existing.id));

    logger.info({ incidentId: existing.id, ruleName }, 'Incident updated');
  } else {
    const [created] = await db
      .insert(incidents)
      .values({ userId, title, severity, ruleName, eventCount: 1, firstSeenAt: firstSeen, lastSeenAt: new Date() })
      .returning({ id: incidents.id });

    logger.warn({ incidentId: created.id, ruleName, title }, 'Incident created');
  }
}

// ── Rules ──────────────────────────────────────────────────────────────────

function userFilter(userId: string | null) {
  return userId ? eq(logEvents.userId, userId) : isNull(logEvents.userId);
}

// Rule 1: Brute Force — 5+ login_failed from same source IP in 2 min
async function evalBruteForce(userId: string | null) {
  const rows = await db
    .select({
      sourceIp: logEvents.sourceIp,
      count:    sql<number>`count(*)::int`,
      firstSeen: sql<Date>`min(${logEvents.createdAt})`,
    })
    .from(logEvents)
    .where(and(
      userFilter(userId),
      eq(logEvents.action, 'login_failed'),
      gte(logEvents.createdAt, windowStart(120)),
      isNotNull(logEvents.sourceIp),
    ))
    .groupBy(logEvents.sourceIp)
    .having(sql`count(*) >= 5`);

  for (const row of rows) {
    await upsertIncident(
      userId,
      `brute_force:${row.sourceIp}`,
      `Brute force detected from ${row.sourceIp} (${row.count} attempts)`,
      'high',
      120,
      row.firstSeen,
    );
  }
}

// Rule 2: Port Scan — 10+ unique destination ports from same source IP in 5 min
async function evalPortScan(userId: string | null) {
  const rows = await db
    .select({
      sourceIp:    logEvents.sourceIp,
      uniquePorts: sql<number>`count(distinct ${logEvents.targetPort})::int`,
      firstSeen:   sql<Date>`min(${logEvents.createdAt})`,
    })
    .from(logEvents)
    .where(and(
      userFilter(userId),
      eq(logEvents.action, 'port_probe'),
      gte(logEvents.createdAt, windowStart(300)),
      isNotNull(logEvents.sourceIp),
      isNotNull(logEvents.targetPort),
    ))
    .groupBy(logEvents.sourceIp)
    .having(sql`count(distinct ${logEvents.targetPort}) >= 10`);

  for (const row of rows) {
    await upsertIncident(
      userId,
      `port_scan:${row.sourceIp}`,
      `Port scan detected from ${row.sourceIp} (${row.uniquePorts} unique ports)`,
      'medium',
      300,
      row.firstSeen,
    );
  }
}

// Rule 3: IOC Spike — 3+ ioc_match events in 10 min
async function evalIocSpike(userId: string | null) {
  const [row] = await db
    .select({
      count:    sql<number>`count(*)::int`,
      firstSeen: sql<Date>`min(${logEvents.createdAt})`,
    })
    .from(logEvents)
    .where(and(
      userFilter(userId),
      eq(logEvents.action, 'ioc_match'),
      gte(logEvents.createdAt, windowStart(600)),
    ));

  if (row && row.count >= 3) {
    await upsertIncident(
      userId,
      'ioc_spike',
      `IOC spike: ${row.count} malicious indicators detected in 10 minutes`,
      'high',
      600,
      row.firstSeen,
    );
  }
}

// Rule 4: Credential Stuffing — 10+ login_failed across 3+ distinct target IPs in 5 min
async function evalCredentialStuffing(userId: string | null) {
  const [row] = await db
    .select({
      total:          sql<number>`count(*)::int`,
      uniqueTargets:  sql<number>`count(distinct ${logEvents.targetIp})::int`,
      firstSeen:      sql<Date>`min(${logEvents.createdAt})`,
    })
    .from(logEvents)
    .where(and(
      userFilter(userId),
      eq(logEvents.action, 'login_failed'),
      gte(logEvents.createdAt, windowStart(300)),
    ));

  if (row && row.total >= 10 && row.uniqueTargets >= 3) {
    await upsertIncident(
      userId,
      'credential_stuffing',
      `Credential stuffing: ${row.total} failed logins across ${row.uniqueTargets} targets`,
      'critical',
      300,
      row.firstSeen,
    );
  }
}

// ── Worker ─────────────────────────────────────────────────────────────────

export function createEventCorrelationWorker() {
  return new Worker(
    'event-correlation',
    async (_job: Job) => {
      const end = jobDuration.startTimer({ queue: 'event-correlation' });

      try {
        // Get all distinct user contexts who have recent events (last 15 min)
        // userId can be null for external sources like the personal website
        const userRows = await db
          .selectDistinct({ userId: logEvents.userId })
          .from(logEvents)
          .where(gte(logEvents.createdAt, windowStart(900)));

        for (const { userId } of userRows) {
          await evalBruteForce(userId);
          await evalPortScan(userId);
          await evalIocSpike(userId);
          await evalCredentialStuffing(userId);
        }

        logger.info({ contexts: userRows.length }, 'Correlation run complete');
        jobsTotal.inc({ queue: 'event-correlation', status: 'completed' });
      } catch (err) {
        logger.error({ err }, 'Correlation run failed');
        jobsTotal.inc({ queue: 'event-correlation', status: 'failed' });
        throw err;
      } finally {
        end();
      }
    },
    { connection: { url: env.REDIS_URL }, concurrency: 1 },
  );
}
