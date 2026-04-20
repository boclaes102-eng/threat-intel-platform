import type { FastifyInstance } from 'fastify';
import { eq, and, desc, lt, gte } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '../../db';
import { logEvents } from '../../db/schema';

const ingestBody = z.object({
  source:     z.string().min(1).max(100),
  category:   z.enum(['auth', 'network', 'threat', 'system', 'recon']),
  action:     z.string().min(1).max(200),
  severity:   z.enum(['critical', 'high', 'medium', 'low', 'info']).default('info'),
  sourceIp:   z.string().ip().optional(),
  targetIp:   z.string().ip().optional(),
  targetPort: z.number().int().min(1).max(65535).optional(),
  message:    z.string().max(2000).optional(),
  rawData:    z.record(z.unknown()).optional(),
});

const listQuery = z.object({
  limit:    z.coerce.number().min(1).max(200).default(50),
  cursor:   z.string().datetime().optional(),
  category: z.enum(['auth', 'network', 'threat', 'system', 'recon']).optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
  source:   z.string().max(100).optional(),
  since:    z.enum(['1h', '6h', '24h', '7d']).default('24h'),
});

const SINCE_MS: Record<string, number> = {
  '1h':  60 * 60 * 1000,
  '6h':  6 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d':  7 * 24 * 60 * 60 * 1000,
};

export default async function eventRoutes(fastify: FastifyInstance) {
  fastify.addHook('onRequest', fastify.authenticate);

  // Ingest a new event
  fastify.post('/events', async (request, reply) => {
    const body = ingestBody.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });
    }

    const [event] = await db
      .insert(logEvents)
      .values({ userId: request.user.id, ...body.data })
      .returning({ id: logEvents.id, createdAt: logEvents.createdAt });

    return reply.status(201).send({ data: event });
  });

  // List events with filters
  fastify.get('/events', async (request, reply) => {
    const query = listQuery.safeParse(request.query);
    if (!query.success) {
      return reply.status(400).send({ error: 'Invalid query', details: query.error.flatten() });
    }

    const { limit, cursor, category, severity, source, since } = query.data;
    const userId = request.user.id;
    const sinceDate = new Date(Date.now() - SINCE_MS[since]);

    const conditions = [
      eq(logEvents.userId, userId),
      gte(logEvents.createdAt, sinceDate),
    ];
    if (cursor)   conditions.push(lt(logEvents.createdAt, new Date(cursor)));
    if (category) conditions.push(eq(logEvents.category, category));
    if (severity) conditions.push(eq(logEvents.severity, severity));
    if (source)   conditions.push(eq(logEvents.source, source));

    const rows = await db
      .select()
      .from(logEvents)
      .where(and(...conditions))
      .orderBy(desc(logEvents.createdAt))
      .limit(limit + 1);

    const hasNext = rows.length > limit;
    const data = hasNext ? rows.slice(0, limit) : rows;

    return {
      data,
      nextCursor: hasNext ? data[data.length - 1].createdAt.toISOString() : null,
    };
  });
}
