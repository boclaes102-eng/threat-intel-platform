import type { FastifyInstance } from 'fastify';
import { eq, and, desc, lt, isNull } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '../../db';
import { alerts, assets } from '../../db/schema';
import { openAlertsGauge } from '../../lib/metrics';

const listQuery = z.object({
  limit: z.coerce.number().min(1).max(100).default(20),
  cursor: z.string().datetime().optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
  type: z.enum(['vulnerability', 'ioc_match', 'scan_complete', 'feed_update']).optional(),
  unread: z.coerce.boolean().optional(),
  assetId: z.string().uuid().optional(),
});

export default async function alertRoutes(fastify: FastifyInstance) {
  fastify.addHook('onRequest', fastify.authenticate);

  fastify.get('/alerts', async (request, reply) => {
    const query = listQuery.safeParse(request.query);
    if (!query.success) {
      return reply.status(400).send({ error: 'Invalid query', details: query.error.flatten() });
    }

    const { limit, cursor, severity, type, unread, assetId } = query.data;
    const userId = request.user.id;

    const conditions = [eq(alerts.userId, userId)];
    if (cursor) conditions.push(lt(alerts.createdAt, new Date(cursor)));
    if (severity) conditions.push(eq(alerts.severity, severity));
    if (type) conditions.push(eq(alerts.type, type));
    if (unread) conditions.push(isNull(alerts.readAt));
    if (assetId) conditions.push(eq(alerts.assetId, assetId));

    const rows = await db
      .select({
        id: alerts.id,
        type: alerts.type,
        severity: alerts.severity,
        title: alerts.title,
        details: alerts.details,
        readAt: alerts.readAt,
        createdAt: alerts.createdAt,
        asset: {
          id: assets.id,
          value: assets.value,
          label: assets.label,
          type: assets.type,
        },
      })
      .from(alerts)
      .leftJoin(assets, eq(alerts.assetId, assets.id))
      .where(and(...conditions))
      .orderBy(desc(alerts.createdAt))
      .limit(limit + 1);

    const hasNext = rows.length > limit;
    const data = hasNext ? rows.slice(0, limit) : rows;

    return {
      data,
      nextCursor: hasNext ? data[data.length - 1].createdAt.toISOString() : null,
    };
  });

  fastify.post<{ Params: { id: string } }>('/alerts/:id/read', async (request, reply) => {
    const alert = await db.query.alerts.findFirst({
      where: and(eq(alerts.id, request.params.id), eq(alerts.userId, request.user.id)),
    });
    if (!alert) return reply.status(404).send({ error: 'Alert not found' });

    await db
      .update(alerts)
      .set({ readAt: new Date() })
      .where(eq(alerts.id, request.params.id));

    openAlertsGauge.dec({ severity: alert.severity });

    return { success: true };
  });

  fastify.post('/alerts/read-all', async (request) => {
    await db
      .update(alerts)
      .set({ readAt: new Date() })
      .where(and(eq(alerts.userId, request.user.id), isNull(alerts.readAt)));

    return { success: true };
  });

  fastify.delete<{ Params: { id: string } }>('/alerts/:id', async (request, reply) => {
    const alert = await db.query.alerts.findFirst({
      where: and(eq(alerts.id, request.params.id), eq(alerts.userId, request.user.id)),
    });
    if (!alert) return reply.status(404).send({ error: 'Alert not found' });

    await db.delete(alerts).where(eq(alerts.id, request.params.id));
    return reply.status(204).send();
  });
}
