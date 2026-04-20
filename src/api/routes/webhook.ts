import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { db } from '../../db';
import { logEvents } from '../../db/schema';
import { env } from '../../lib/env';
import { logger } from '../../lib/logger';

const eventBody = z.object({
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

export default async function webhookRoutes(fastify: FastifyInstance) {
  // Unauthenticated ingest for external sources (personal website, scripts, etc.)
  // Protected by a shared secret in the X-Webhook-Secret header.
  fastify.post('/webhook/site-events', async (request, reply) => {
    if (!env.SIEM_WEBHOOK_SECRET) {
      return reply.status(503).send({ error: 'Webhook not configured' });
    }

    const secret = request.headers['x-webhook-secret'];
    if (secret !== env.SIEM_WEBHOOK_SECRET) {
      logger.warn({ ip: request.ip }, 'Webhook: invalid secret');
      return reply.status(401).send({ error: 'Unauthorized' });
    }

    const body = eventBody.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });
    }

    await db.insert(logEvents).values({ userId: null, ...body.data });

    return reply.status(201).send({ ok: true });
  });
}
