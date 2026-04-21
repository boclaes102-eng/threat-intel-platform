import Fastify from 'fastify';
import fastifyCors from '@fastify/cors';
import fastifyRateLimit from '@fastify/rate-limit';
import fastifySwagger from '@fastify/swagger';
import fastifySwaggerUi from '@fastify/swagger-ui';
import { randomUUID } from 'crypto';
import { env } from '../lib/env';
import { logger } from '../lib/logger';
import { redis } from '../lib/redis';
import { httpRequestsTotal, httpRequestDuration } from '../lib/metrics';

import authPlugin from './plugins/auth';
import healthRoutes from './routes/health';
import authRoutes from './routes/auth';
import assetRoutes from './routes/assets';
import alertRoutes from './routes/alerts';
import vulnerabilityRoutes from './routes/vulnerabilities';
import iocRoutes from './routes/ioc';
import reconSessionRoutes from './routes/recon-sessions';
import eventRoutes from './routes/events';
import incidentRoutes from './routes/incidents';
import webhookRoutes from './routes/webhook';
import debugRoutes from './routes/debug';

export async function buildServer() {
  console.log('[server] buildServer() called');
  const fastify = Fastify({
    logger: false,
    trustProxy: true,
    // Accept X-Request-ID from caller, or mint a fresh UUID
    genReqId: (req) => (req.headers['x-request-id'] as string) || randomUUID(),
  });

  console.log('[server] registering swagger');
  // ── OpenAPI / Swagger ────────────────────────────────────────────────────
  await fastify.register(fastifySwagger, {
    openapi: {
      openapi: '3.0.3',
      info: {
        title: 'Threat Intelligence Platform API',
        description: 'Asset monitoring, CVE tracking, and IOC enrichment backend. Pairs with Online-Cyber-Dashboard.',
        version: '1.0.0',
        contact: { name: 'API Support', email: 'admin@threat-intel.local' },
      },
      servers: [
        { url: 'http://localhost:3001', description: 'Local development' },
        { url: 'http://api:3001', description: 'Docker compose' },
      ],
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', description: 'Short-lived access token from /auth/login (15 min)' },
          apiKey: { type: 'apiKey', in: 'header', name: 'X-API-Key', description: 'Long-lived API key for server-to-server calls — create via POST /auth/api-keys' },
        },
      },
      security: [{ bearerAuth: [] }, { apiKey: [] }],
    },
  });

  await fastify.register(fastifySwaggerUi, {
    routePrefix: '/docs',
    uiConfig: { docExpansion: 'list', deepLinking: false, persistAuthorization: true },
    staticCSP: true,
  });

  // ── CORS ─────────────────────────────────────────────────────────────────
  await fastify.register(fastifyCors, {
    origin: env.CORS_ORIGIN.split(',').map((o) => o.trim()),
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    credentials: true,
    exposedHeaders: ['X-Request-ID'],
  });

  console.log('[server] registering rate-limit');
  // ── Rate limiting ─────────────────────────────────────────────────────────
  await fastify.register(fastifyRateLimit, {
    max: 120,
    timeWindow: '1 minute',
    redis,
    keyGenerator: (request) => request.headers['x-forwarded-for']?.toString() ?? request.ip,
    errorResponseBuilder: () => ({ error: 'Too many requests', message: 'Rate limit exceeded. Please slow down.' }),
  });

  console.log('[server] registering auth plugin');
  // ── Auth plugin (JWT + API key) ───────────────────────────────────────────
  await fastify.register(authPlugin);

  // ── Echo X-Request-ID on every response ──────────────────────────────────
  fastify.addHook('onSend', (request, reply, payload, done) => {
    reply.header('X-Request-ID', request.id);
    done(null, payload);
  });

  // ── Prometheus metrics + structured logging ──────────────────────────────
  fastify.addHook('onResponse', (request, reply, done) => {
    const route = (request.routerPath ?? request.url).split('?')[0];
    const labels = { method: request.method, route, status: String(reply.statusCode) };
    httpRequestsTotal.inc(labels);
    httpRequestDuration.observe(labels, reply.elapsedTime / 1000);

    logger.info(
      { reqId: request.id, method: request.method, url: request.url, status: reply.statusCode, ms: reply.elapsedTime.toFixed(1) },
      'request',
    );
    done();
  });

  console.log('[server] registering routes');
  // ── Routes ────────────────────────────────────────────────────────────────
  const prefix = '/api/v1';
  await fastify.register(healthRoutes);
  await fastify.register(authRoutes, { prefix });
  await fastify.register(assetRoutes, { prefix });
  await fastify.register(alertRoutes, { prefix });
  await fastify.register(vulnerabilityRoutes, { prefix });
  await fastify.register(iocRoutes, { prefix });
  await fastify.register(reconSessionRoutes, { prefix });
  await fastify.register(eventRoutes, { prefix });
  await fastify.register(incidentRoutes, { prefix });
  await fastify.register(debugRoutes,    { prefix });
  await fastify.register(webhookRoutes);

  fastify.setNotFoundHandler((_, reply) => reply.status(404).send({ error: 'Not found' }));
  fastify.setErrorHandler((err, request, reply) => {
    logger.error({ err, reqId: request.id, url: request.url }, 'Unhandled error');
    reply.status(500).send({ error: 'Internal server error' });
  });

  console.log('[server] buildServer() done');
  return fastify;
}
