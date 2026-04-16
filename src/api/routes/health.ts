import type { FastifyInstance } from 'fastify';
import { db } from '../../db';
import { redis } from '../../lib/redis';
import { registry } from '../../lib/metrics';
import { sql } from 'drizzle-orm';

export default async function healthRoutes(fastify: FastifyInstance) {
  fastify.get('/health', async (_, reply) => {
    const checks: Record<string, 'ok' | 'error'> = {};

    try {
      await db.execute(sql`SELECT 1`);
      checks.postgres = 'ok';
    } catch {
      checks.postgres = 'error';
    }

    try {
      await redis.ping();
      checks.redis = 'ok';
    } catch {
      checks.redis = 'error';
    }

    const allOk = Object.values(checks).every((v) => v === 'ok');
    reply.status(allOk ? 200 : 503).send({
      status: allOk ? 'ok' : 'degraded',
      checks,
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    });
  });

  fastify.get('/metrics', async (_, reply) => {
    reply.header('Content-Type', registry.contentType);
    return registry.metrics();
  });
}
