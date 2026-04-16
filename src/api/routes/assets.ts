import type { FastifyInstance } from 'fastify';
import { eq, and, desc, lt } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '../../db';
import { assets } from '../../db/schema';
import { iocScanQueue, assetScanQueue } from '../../workers/queues';
import { activeAssetsGauge } from '../../lib/metrics';

const createAssetBody = z.object({
  type: z.enum(['ip', 'domain', 'cidr', 'url']),
  value: z.string().min(1).max(512),
  label: z.string().max(255).optional(),
  tags: z.array(z.string()).max(20).default([]),
});

const listQuery = z.object({
  limit: z.coerce.number().min(1).max(100).default(20),
  cursor: z.string().datetime().optional(),
  type: z.enum(['ip', 'domain', 'cidr', 'url']).optional(),
  active: z.coerce.boolean().optional(),
});

export default async function assetRoutes(fastify: FastifyInstance) {
  fastify.addHook('onRequest', fastify.authenticate);

  fastify.get('/assets', async (request) => {
    const query = listQuery.safeParse(request.query);
    if (!query.success) return { error: 'Invalid query', details: query.error.flatten() };

    const { limit, cursor, type, active } = query.data;
    const userId = request.user.id;

    const conditions = [eq(assets.userId, userId)];
    if (cursor) conditions.push(lt(assets.createdAt, new Date(cursor)));
    if (type) conditions.push(eq(assets.type, type));
    if (active !== undefined) conditions.push(eq(assets.active, active));

    const rows = await db
      .select()
      .from(assets)
      .where(and(...conditions))
      .orderBy(desc(assets.createdAt))
      .limit(limit + 1);

    const hasNext = rows.length > limit;
    const data = hasNext ? rows.slice(0, limit) : rows;

    return {
      data,
      nextCursor: hasNext ? data[data.length - 1].createdAt.toISOString() : null,
      total: data.length,
    };
  });

  fastify.get<{ Params: { id: string } }>('/assets/:id', async (request, reply) => {
    const asset = await db.query.assets.findFirst({
      where: and(eq(assets.id, request.params.id), eq(assets.userId, request.user.id)),
    });
    if (!asset) return reply.status(404).send({ error: 'Asset not found' });
    return { data: asset };
  });

  fastify.post('/assets', async (request, reply) => {
    const body = createAssetBody.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });
    }

    const [asset] = await db
      .insert(assets)
      .values({ ...body.data, userId: request.user.id })
      .returning()
      .catch((err: Error) => {
        if (err.message.includes('unique')) {
          throw reply.status(409).send({ error: 'Asset already registered' });
        }
        throw err;
      });

    // Queue IOC scan immediately for IP/domain assets
    if (asset.type === 'ip' || asset.type === 'domain') {
      await iocScanQueue.add('scan', {
        assetId: asset.id,
        indicator: asset.value,
        userId: asset.userId,
      });
    }

    // Queue asset correlation scan
    await assetScanQueue.add('correlate', { assetId: asset.id, userId: asset.userId });

    activeAssetsGauge.inc();

    return reply.status(201).send({ data: asset });
  });

  fastify.patch<{ Params: { id: string } }>('/assets/:id', async (request, reply) => {
    const patchBody = z
      .object({ label: z.string().max(255).optional(), tags: z.array(z.string()).optional(), active: z.boolean().optional() })
      .safeParse(request.body);
    if (!patchBody.success) {
      return reply.status(400).send({ error: 'Validation error' });
    }

    const existing = await db.query.assets.findFirst({
      where: and(eq(assets.id, request.params.id), eq(assets.userId, request.user.id)),
    });
    if (!existing) return reply.status(404).send({ error: 'Asset not found' });

    const [updated] = await db
      .update(assets)
      .set(patchBody.data)
      .where(eq(assets.id, request.params.id))
      .returning();

    if (patchBody.data.active === false) activeAssetsGauge.dec();

    return { data: updated };
  });

  fastify.delete<{ Params: { id: string } }>('/assets/:id', async (request, reply) => {
    const existing = await db.query.assets.findFirst({
      where: and(eq(assets.id, request.params.id), eq(assets.userId, request.user.id)),
    });
    if (!existing) return reply.status(404).send({ error: 'Asset not found' });

    await db.delete(assets).where(eq(assets.id, request.params.id));
    if (existing.active) activeAssetsGauge.dec();

    return reply.status(204).send();
  });
}
