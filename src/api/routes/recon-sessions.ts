import type { FastifyInstance } from 'fastify';
import { eq, and, desc, lt } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '../../db';
import { reconSessions } from '../../db/schema';

const RECON_TOOLS = [
  'ip', 'domain', 'subdomains', 'ssl', 'headers', 'portscan',
  'dns', 'reverseip', 'asn', 'whoishistory', 'certs', 'traceroute',
  'url', 'email', 'ioc', 'shodan', 'tech', 'waf', 'cors',
] as const;

const createBody = z.object({
  tool:    z.enum(RECON_TOOLS),
  target:  z.string().min(1).max(512),
  summary: z.record(z.unknown()).default({}),
  results: z.record(z.unknown()).default({}),
  tags:    z.array(z.string().max(64)).max(20).default([]),
  notes:   z.string().max(4000).optional(),
});

const listQuery = z.object({
  limit:  z.coerce.number().min(1).max(100).default(20),
  cursor: z.string().datetime().optional(),
  tool:   z.enum(RECON_TOOLS).optional(),
  target: z.string().optional(),
});

export default async function reconSessionRoutes(fastify: FastifyInstance) {
  fastify.addHook('onRequest', fastify.authenticate);

  // ── List ──────────────────────────────────────────────────────────────────
  fastify.get('/recon-sessions', async (request) => {
    const q = listQuery.safeParse(request.query);
    if (!q.success) return { error: 'Invalid query', details: q.error.flatten() };

    const { limit, cursor, tool, target } = q.data;
    const userId = request.user.id;

    const conditions = [eq(reconSessions.userId, userId)];
    if (cursor)  conditions.push(lt(reconSessions.createdAt, new Date(cursor)));
    if (tool)    conditions.push(eq(reconSessions.tool, tool));
    if (target)  conditions.push(eq(reconSessions.target, target));

    const rows = await db
      .select()
      .from(reconSessions)
      .where(and(...conditions))
      .orderBy(desc(reconSessions.createdAt))
      .limit(limit + 1);

    const hasNext = rows.length > limit;
    const data = hasNext ? rows.slice(0, limit) : rows;
    return {
      data,
      nextCursor: hasNext ? data[data.length - 1].createdAt.toISOString() : null,
      total: data.length,
    };
  });

  // ── Detail ────────────────────────────────────────────────────────────────
  fastify.get<{ Params: { id: string } }>('/recon-sessions/:id', async (request, reply) => {
    const session = await db.query.reconSessions.findFirst({
      where: and(eq(reconSessions.id, request.params.id), eq(reconSessions.userId, request.user.id)),
    });
    if (!session) return reply.status(404).send({ error: 'Recon session not found' });
    return { data: session };
  });

  // ── Create ────────────────────────────────────────────────────────────────
  fastify.post('/recon-sessions', async (request, reply) => {
    const body = createBody.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });
    }

    const [session] = await db
      .insert(reconSessions)
      .values({ ...body.data, userId: request.user.id })
      .returning();

    return reply.status(201).send({ data: session });
  });

  // ── Update notes / tags ───────────────────────────────────────────────────
  fastify.patch<{ Params: { id: string } }>('/recon-sessions/:id', async (request, reply) => {
    const patchBody = z
      .object({
        tags:  z.array(z.string().max(64)).max(20).optional(),
        notes: z.string().max(4000).optional(),
      })
      .safeParse(request.body);
    if (!patchBody.success) return reply.status(400).send({ error: 'Validation error' });

    const existing = await db.query.reconSessions.findFirst({
      where: and(eq(reconSessions.id, request.params.id), eq(reconSessions.userId, request.user.id)),
    });
    if (!existing) return reply.status(404).send({ error: 'Recon session not found' });

    const [updated] = await db
      .update(reconSessions)
      .set(patchBody.data)
      .where(eq(reconSessions.id, request.params.id))
      .returning();

    return { data: updated };
  });

  // ── Delete ────────────────────────────────────────────────────────────────
  fastify.delete<{ Params: { id: string } }>('/recon-sessions/:id', async (request, reply) => {
    const existing = await db.query.reconSessions.findFirst({
      where: and(eq(reconSessions.id, request.params.id), eq(reconSessions.userId, request.user.id)),
    });
    if (!existing) return reply.status(404).send({ error: 'Recon session not found' });

    await db.delete(reconSessions).where(eq(reconSessions.id, request.params.id));
    return reply.status(204).send();
  });
}
