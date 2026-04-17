import type { FastifyInstance } from 'fastify';
import { eq, and, isNull, gt } from 'drizzle-orm';
import { createHash, randomBytes } from 'crypto';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { db } from '../../db';
import { users, refreshTokens, apiKeys } from '../../db/schema';
import { env } from '../../lib/env';

const registerBody = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(72),
});

const loginBody = z.object({
  email: z.string().email(),
  password: z.string(),
});

function generateRefreshToken() {
  return randomBytes(64).toString('hex');
}

function hashToken(token: string) {
  return createHash('sha256').update(token).digest('hex');
}

function refreshTokenExpiry() {
  return new Date(Date.now() + env.REFRESH_TOKEN_EXPIRY_DAYS * 86_400_000);
}

export default async function authRoutes(fastify: FastifyInstance) {
  // ── Register ──────────────────────────────────────────────────────────────
  fastify.post(
    '/auth/register',
    {
      schema: {
        body: { type: 'object', required: ['email', 'password'], properties: { email: { type: 'string', format: 'email' }, password: { type: 'string', minLength: 8 } } },
        response: { 201: { type: 'object', properties: { accessToken: { type: 'string' }, refreshToken: { type: 'string' }, user: { type: 'object', additionalProperties: true } } } },
      },
    },
    async (request, reply) => {
      const body = registerBody.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });
      }

      const { email, password } = body.data;
      const existing = await db.query.users.findFirst({ where: eq(users.email, email) });
      if (existing) return reply.status(409).send({ error: 'Email already registered' });

      const passwordHash = await bcrypt.hash(password, 12);
      const [user] = await db
        .insert(users)
        .values({ email, passwordHash })
        .returning({ id: users.id, email: users.email, createdAt: users.createdAt });

      const accessToken = fastify.jwt.sign({ id: user.id, email: user.email });
      const rawRefresh = generateRefreshToken();
      await db.insert(refreshTokens).values({
        userId: user.id,
        tokenHash: hashToken(rawRefresh),
        expiresAt: refreshTokenExpiry(),
      });

      return reply.status(201).send({ accessToken, refreshToken: rawRefresh, user });
    },
  );

  // ── Login ─────────────────────────────────────────────────────────────────
  fastify.post(
    '/auth/login',
    {
      schema: {
        body: { type: 'object', required: ['email', 'password'], properties: { email: { type: 'string', format: 'email' }, password: { type: 'string' } } },
        response: { 200: { type: 'object', properties: { accessToken: { type: 'string' }, refreshToken: { type: 'string' }, expiresIn: { type: 'number' }, user: { type: 'object' } } } },
      },
    },
    async (request, reply) => {
      const body = loginBody.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({ error: 'Validation error', details: body.error.flatten() });
      }

      const { email, password } = body.data;
      const user = await db.query.users.findFirst({ where: eq(users.email, email) });
      if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        return reply.status(401).send({ error: 'Invalid credentials' });
      }

      const accessToken = fastify.jwt.sign({ id: user.id, email: user.email });
      const rawRefresh = generateRefreshToken();
      await db.insert(refreshTokens).values({
        userId: user.id,
        tokenHash: hashToken(rawRefresh),
        expiresAt: refreshTokenExpiry(),
      });

      return {
        accessToken,
        refreshToken: rawRefresh,
        expiresIn: 900, // 15 minutes in seconds
        user: { id: user.id, email: user.email, createdAt: user.createdAt },
      };
    },
  );

  // ── Refresh ───────────────────────────────────────────────────────────────
  fastify.post('/auth/refresh', async (request, reply) => {
    const body = z.object({ refreshToken: z.string().min(1) }).safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'refreshToken is required' });

    const hash = hashToken(body.data.refreshToken);
    const record = await db.query.refreshTokens.findFirst({
      where: and(
        eq(refreshTokens.tokenHash, hash),
        isNull(refreshTokens.revokedAt),
        gt(refreshTokens.expiresAt, new Date()),
      ),
    });

    if (!record) return reply.status(401).send({ error: 'Invalid or expired refresh token' });

    const user = await db.query.users.findFirst({
      where: eq(users.id, record.userId),
      columns: { id: true, email: true },
    });
    if (!user) return reply.status(401).send({ error: 'User not found' });

    const accessToken = fastify.jwt.sign({ id: user.id, email: user.email });
    return { accessToken, expiresIn: 900 };
  });

  // ── Logout ────────────────────────────────────────────────────────────────
  fastify.post('/auth/logout', { onRequest: [fastify.authenticate] }, async (request) => {
    const body = z.object({ refreshToken: z.string().optional() }).safeParse(request.body);
    if (body.success && body.data.refreshToken) {
      const hash = hashToken(body.data.refreshToken);
      await db
        .update(refreshTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(refreshTokens.tokenHash, hash), eq(refreshTokens.userId, request.user.id)));
    }
    return { success: true };
  });

  // ── Me ────────────────────────────────────────────────────────────────────
  fastify.get('/auth/me', { onRequest: [fastify.authenticate] }, async (request) => {
    const user = await db.query.users.findFirst({
      where: eq(users.id, request.user.id),
      columns: { id: true, email: true, createdAt: true },
    });
    return { user };
  });

  // ── API Keys ──────────────────────────────────────────────────────────────
  fastify.get('/auth/api-keys', { onRequest: [fastify.authenticate] }, async (request) => {
    const keys = await db
      .select({ id: apiKeys.id, name: apiKeys.name, createdAt: apiKeys.createdAt, lastUsedAt: apiKeys.lastUsedAt, revokedAt: apiKeys.revokedAt })
      .from(apiKeys)
      .where(eq(apiKeys.userId, request.user.id));
    return { data: keys };
  });

  fastify.post('/auth/api-keys', { onRequest: [fastify.authenticate] }, async (request, reply) => {
    const body = z.object({ name: z.string().min(1).max(100) }).safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: 'name is required' });

    // Generate a prefixed key: tip_<64 hex chars>
    const rawKey = `tip_${randomBytes(32).toString('hex')}`;
    const keyHash = createHash('sha256').update(rawKey).digest('hex');

    const [key] = await db
      .insert(apiKeys)
      .values({ userId: request.user.id, keyHash, name: body.data.name })
      .returning({ id: apiKeys.id, name: apiKeys.name, createdAt: apiKeys.createdAt });

    // The raw key is only returned once — it cannot be recovered after this point
    return reply.status(201).send({ data: { ...key, key: rawKey } });
  });

  fastify.delete<{ Params: { id: string } }>(
    '/auth/api-keys/:id',
    { onRequest: [fastify.authenticate] },
    async (request, reply) => {
      const existing = await db.query.apiKeys.findFirst({
        where: and(eq(apiKeys.id, request.params.id), eq(apiKeys.userId, request.user.id)),
      });
      if (!existing) return reply.status(404).send({ error: 'API key not found' });

      await db
        .update(apiKeys)
        .set({ revokedAt: new Date() })
        .where(eq(apiKeys.id, request.params.id));

      return reply.status(204).send();
    },
  );
}
