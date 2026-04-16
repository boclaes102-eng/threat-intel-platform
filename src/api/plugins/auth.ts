import fp from 'fastify-plugin';
import fastifyJwt from '@fastify/jwt';
import { createHash } from 'crypto';
import { eq, and, isNull, gt } from 'drizzle-orm';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { db } from '../../db';
import { apiKeys, users } from '../../db/schema';
import { env } from '../../lib/env';

declare module '@fastify/jwt' {
  interface FastifyJWT {
    user: { id: string; email: string };
  }
}

async function lookupApiKey(rawKey: string): Promise<{ id: string; email: string } | null> {
  const hash = createHash('sha256').update(rawKey).digest('hex');

  const [row] = await db
    .select({ userId: apiKeys.userId, email: users.email, keyId: apiKeys.id })
    .from(apiKeys)
    .innerJoin(users, eq(apiKeys.userId, users.id))
    .where(and(eq(apiKeys.keyHash, hash), isNull(apiKeys.revokedAt)))
    .limit(1);

  if (!row) return null;

  // Touch last_used_at without blocking the request
  db.update(apiKeys)
    .set({ lastUsedAt: new Date() })
    .where(eq(apiKeys.id, row.keyId))
    .catch(() => {});

  return { id: row.userId, email: row.email };
}

export default fp(async function authPlugin(fastify: FastifyInstance) {
  await fastify.register(fastifyJwt, {
    secret: env.JWT_SECRET,
    sign: { expiresIn: env.ACCESS_TOKEN_EXPIRY },
  });

  fastify.decorate(
    'authenticate',
    async function (request: FastifyRequest, reply: FastifyReply) {
      const apiKey = request.headers['x-api-key'];

      if (typeof apiKey === 'string' && apiKey.length > 0) {
        const user = await lookupApiKey(apiKey);
        if (!user) {
          return reply.status(401).send({ error: 'Invalid API key' });
        }
        request.user = user;
        return;
      }

      try {
        await request.jwtVerify();
      } catch {
        reply.status(401).send({ error: 'Unauthorized', message: 'Invalid or expired token' });
      }
    },
  );
});

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}
