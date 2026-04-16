import type { FastifyInstance } from 'fastify';
import { eq, lt, and, desc } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '../../db';
import { iocRecords } from '../../db/schema';
import { enrichIoc } from '../../services/ioc-enrichment';

const listQuery = z.object({
  limit: z.coerce.number().min(1).max(100).default(20),
  cursor: z.string().datetime().optional(),
  verdict: z.enum(['malicious', 'suspicious', 'clean', 'unknown']).optional(),
});

export default async function iocRoutes(fastify: FastifyInstance) {
  fastify.addHook('onRequest', fastify.authenticate);

  // On-demand IOC lookup — checks cache (Redis), then DB, then enriches if stale
  fastify.get<{ Params: { indicator: string } }>('/ioc/:indicator', async (request) => {
    const indicator = decodeURIComponent(request.params.indicator);

    // Check DB for a non-expired record first
    const existing = await db.query.iocRecords.findFirst({
      where: eq(iocRecords.indicator, indicator),
    });

    if (existing && existing.expiresAt > new Date()) {
      return { data: existing, cached: true };
    }

    // Enrich fresh (enrichIoc handles Redis cache internally)
    const result = await enrichIoc(indicator);
    return { data: result, cached: false };
  });

  // List all IOC records in the database
  fastify.get('/ioc', async (request, reply) => {
    const query = listQuery.safeParse(request.query);
    if (!query.success) {
      return reply.status(400).send({ error: 'Invalid query' });
    }

    const { limit, cursor, verdict } = query.data;

    const conditions = [];
    if (cursor) conditions.push(lt(iocRecords.createdAt, new Date(cursor)));
    if (verdict) conditions.push(eq(iocRecords.verdict, verdict));

    const rows = await db
      .select()
      .from(iocRecords)
      .where(conditions.length ? and(...conditions) : undefined)
      .orderBy(desc(iocRecords.lastChecked))
      .limit(limit + 1);

    const hasNext = rows.length > limit;
    const data = hasNext ? rows.slice(0, limit) : rows;

    return {
      data,
      nextCursor: hasNext ? data[data.length - 1].createdAt.toISOString() : null,
    };
  });
}
