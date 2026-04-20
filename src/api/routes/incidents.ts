import type { FastifyInstance } from 'fastify';
import { eq, and, desc, lt } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '../../db';
import { incidents } from '../../db/schema';

const listQuery = z.object({
  limit:    z.coerce.number().min(1).max(100).default(20),
  cursor:   z.string().datetime().optional(),
  status:   z.enum(['open', 'investigating', 'resolved']).optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
});

const patchBody = z.object({
  status: z.enum(['open', 'investigating', 'resolved']),
});

export default async function incidentRoutes(fastify: FastifyInstance) {
  fastify.addHook('onRequest', fastify.authenticate);

  // List incidents
  fastify.get('/incidents', async (request, reply) => {
    const query = listQuery.safeParse(request.query);
    if (!query.success) {
      return reply.status(400).send({ error: 'Invalid query', details: query.error.flatten() });
    }

    const { limit, cursor, status, severity } = query.data;
    const userId = request.user.id;

    const conditions = [eq(incidents.userId, userId)];
    if (cursor)   conditions.push(lt(incidents.createdAt, new Date(cursor)));
    if (status)   conditions.push(eq(incidents.status, status));
    if (severity) conditions.push(eq(incidents.severity, severity));

    const rows = await db
      .select()
      .from(incidents)
      .where(and(...conditions))
      .orderBy(desc(incidents.createdAt))
      .limit(limit + 1);

    const hasNext = rows.length > limit;
    const data = hasNext ? rows.slice(0, limit) : rows;

    return {
      data,
      nextCursor: hasNext ? data[data.length - 1].createdAt.toISOString() : null,
    };
  });

  // Update incident status
  fastify.patch<{ Params: { id: string } }>('/incidents/:id', async (request, reply) => {
    const body = patchBody.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });
    }

    const incident = await db.query.incidents.findFirst({
      where: and(eq(incidents.id, request.params.id), eq(incidents.userId, request.user.id)),
    });
    if (!incident) return reply.status(404).send({ error: 'Incident not found' });

    const update: Partial<typeof incidents.$inferInsert> = {
      status:    body.data.status,
      updatedAt: new Date(),
    };
    if (body.data.status === 'resolved') update.resolvedAt = new Date();

    await db.update(incidents).set(update).where(eq(incidents.id, request.params.id));

    return { success: true };
  });
}
