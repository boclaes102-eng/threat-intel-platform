import type { FastifyInstance } from 'fastify';
import { eq, and, desc, lt, ilike } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '../../db';
import { vulnerabilities, assetVulnerabilities, assets } from '../../db/schema';

const listQuery = z.object({
  limit: z.coerce.number().min(1).max(100).default(20),
  cursor: z.string().datetime().optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'none']).optional(),
  assetId: z.string().uuid().optional(),
  search: z.string().max(100).optional(),
  status: z.enum(['open', 'acknowledged', 'remediated', 'false_positive']).optional(),
});

export default async function vulnerabilityRoutes(fastify: FastifyInstance) {
  fastify.addHook('onRequest', fastify.authenticate);

  // List vulnerabilities — optionally scoped to a specific asset via join
  fastify.get('/vulnerabilities', async (request, reply) => {
    const query = listQuery.safeParse(request.query);
    if (!query.success) {
      return reply.status(400).send({ error: 'Invalid query', details: query.error.flatten() });
    }

    const { limit, cursor, severity, assetId, search, status } = query.data;
    const userId = request.user.id;

    if (assetId) {
      // Asset-scoped query: join asset_vulnerabilities to show status per asset
      const asset = await db.query.assets.findFirst({
        where: and(eq(assets.id, assetId), eq(assets.userId, userId)),
      });
      if (!asset) return reply.status(404).send({ error: 'Asset not found' });

      const conditions = [eq(assetVulnerabilities.assetId, assetId)];
      if (status) conditions.push(eq(assetVulnerabilities.status, status));

      const rows = await db
        .select({
          id: vulnerabilities.id,
          cveId: vulnerabilities.cveId,
          title: vulnerabilities.title,
          description: vulnerabilities.description,
          severity: vulnerabilities.severity,
          cvssScore: vulnerabilities.cvssScore,
          cvssVector: vulnerabilities.cvssVector,
          publishedAt: vulnerabilities.publishedAt,
          affectedProducts: vulnerabilities.affectedProducts,
          linkStatus: assetVulnerabilities.status,
          discoveredAt: assetVulnerabilities.discoveredAt,
        })
        .from(assetVulnerabilities)
        .innerJoin(vulnerabilities, eq(assetVulnerabilities.vulnerabilityId, vulnerabilities.id))
        .where(and(...conditions))
        .orderBy(desc(assetVulnerabilities.discoveredAt))
        .limit(limit + 1);

      const hasNext = rows.length > limit;
      const data = hasNext ? rows.slice(0, limit) : rows;
      return { data, nextCursor: hasNext ? data[data.length - 1].discoveredAt.toISOString() : null };
    }

    // User-scoped CVE list — only CVEs linked to this user's assets
    const vulnConditions = [eq(assets.userId, userId)];
    if (cursor)   vulnConditions.push(lt(vulnerabilities.publishedAt, new Date(cursor)));
    if (severity) vulnConditions.push(eq(vulnerabilities.severity, severity));
    if (search)   vulnConditions.push(ilike(vulnerabilities.cveId, `%${search}%`));

    const rows = await db
      .selectDistinct({
        id:               vulnerabilities.id,
        cveId:            vulnerabilities.cveId,
        title:            vulnerabilities.title,
        description:      vulnerabilities.description,
        severity:         vulnerabilities.severity,
        cvssScore:        vulnerabilities.cvssScore,
        cvssVector:       vulnerabilities.cvssVector,
        publishedAt:      vulnerabilities.publishedAt,
        affectedProducts: vulnerabilities.affectedProducts,
        createdAt:        vulnerabilities.createdAt,
      })
      .from(vulnerabilities)
      .innerJoin(assetVulnerabilities, eq(assetVulnerabilities.vulnerabilityId, vulnerabilities.id))
      .innerJoin(assets, and(eq(assets.id, assetVulnerabilities.assetId), eq(assets.userId, userId)))
      .where(and(...vulnConditions))
      .orderBy(desc(vulnerabilities.publishedAt))
      .limit(limit + 1);

    const hasNext = rows.length > limit;
    const data = hasNext ? rows.slice(0, limit) : rows;
    return { data, nextCursor: hasNext ? data[data.length - 1].publishedAt.toISOString() : null };
  });

  fastify.get<{ Params: { cveId: string } }>('/vulnerabilities/:cveId', async (request, reply) => {
    const vuln = await db.query.vulnerabilities.findFirst({
      where: eq(vulnerabilities.cveId, request.params.cveId.toUpperCase()),
    });
    if (!vuln) return reply.status(404).send({ error: 'CVE not found' });
    return { data: vuln };
  });

  // Update vulnerability status on a specific asset
  fastify.patch<{ Params: { assetId: string; cveId: string } }>(
    '/assets/:assetId/vulnerabilities/:cveId',
    async (request, reply) => {
      const body = z.object({
        status: z.enum(['open', 'acknowledged', 'remediated', 'false_positive']),
      }).safeParse(request.body);
      if (!body.success) return reply.status(400).send({ error: 'Validation error' });

      const asset = await db.query.assets.findFirst({
        where: and(eq(assets.id, request.params.assetId), eq(assets.userId, request.user.id)),
      });
      if (!asset) return reply.status(404).send({ error: 'Asset not found' });

      const vuln = await db.query.vulnerabilities.findFirst({
        where: eq(vulnerabilities.cveId, request.params.cveId.toUpperCase()),
      });
      if (!vuln) return reply.status(404).send({ error: 'CVE not found' });

      await db
        .update(assetVulnerabilities)
        .set({ status: body.data.status, updatedAt: new Date() })
        .where(
          and(
            eq(assetVulnerabilities.assetId, request.params.assetId),
            eq(assetVulnerabilities.vulnerabilityId, vuln.id),
          ),
        );

      return { success: true };
    },
  );
}
