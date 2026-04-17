import type { FastifyInstance } from 'fastify';
import { registry } from '../../lib/metrics';

export default async function healthRoutes(fastify: FastifyInstance) {
  fastify.get('/health', async (_, reply) => {
    reply.status(200).send({ status: 'ok' });
  });

  fastify.get('/metrics', async (_, reply) => {
    reply.header('Content-Type', registry.contentType);
    return registry.metrics();
  });
}
