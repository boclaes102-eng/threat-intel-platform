import type { FastifyInstance } from 'fastify';
import { eq, and, gte, isNull, sql } from 'drizzle-orm';
import { db } from '../../db';
import { logEvents, incidents } from '../../db/schema';

function windowStart(seconds: number) {
  return new Date(Date.now() - seconds * 1000);
}

export default async function debugRoutes(fastify: FastifyInstance) {
  fastify.addHook('onRequest', fastify.authenticate);

  // Shows exactly what the correlation worker sees right now
  fastify.get('/debug/correlation', async () => {
    const [loginFailed120s] = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(logEvents)
      .where(and(
        eq(logEvents.action, 'login_failed'),
        gte(logEvents.createdAt, windowStart(120)),
        isNull(logEvents.sourceIp),
      ));

    const [loginFailed24h] = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(logEvents)
      .where(and(
        eq(logEvents.action, 'login_failed'),
        gte(logEvents.createdAt, windowStart(86400)),
      ));

    const allIncidents = await db.select().from(incidents).limit(10);

    const recentEvents = await db
      .select({ action: logEvents.action, source: logEvents.source, createdAt: logEvents.createdAt, userId: logEvents.userId })
      .from(logEvents)
      .where(gte(logEvents.createdAt, windowStart(300)))
      .limit(20);

    return {
      bruteForceCheck: {
        loginFailedInLast120s_nullIp: loginFailed120s.count,
        threshold: 5,
        wouldFire: loginFailed120s.count >= 5,
      },
      loginFailed24hTotal: loginFailed24h.count,
      incidentsInDb: allIncidents.length,
      incidents: allIncidents,
      recentEvents,
    };
  });
}
