import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../../src/api/server';
import { db } from '../../../src/db';
import { iocRecords } from '../../../src/db/schema';

vi.mock('../../../src/workers/queues', () => ({
  iocScanQueue: { add: vi.fn().mockResolvedValue(undefined) },
  assetScanQueue: { add: vi.fn().mockResolvedValue(undefined) },
  cveFeedQueue: { add: vi.fn().mockResolvedValue(undefined) },
  scheduleRecurringJobs: vi.fn().mockResolvedValue(undefined),
}));

// Mock external enrichment so tests don't call real APIs
vi.mock('../../../src/services/ioc-enrichment', () => ({
  enrichIoc: vi.fn().mockResolvedValue({
    indicator: '1.2.3.4',
    type: 'ip',
    verdict: 'clean',
    score: 0,
    sources: {},
    lastChecked: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  }),
}));

let server: FastifyInstance;
let authToken: string;

beforeAll(async () => {
  server = await buildServer();
  await server.ready();

  const reg = await server.inject({
    method: 'POST',
    url: '/api/v1/auth/register',
    payload: { email: 'ioc-test@example.com', password: 'password123' },
  });
  authToken = reg.json().accessToken;
});

afterAll(async () => {
  await server.close();
});

async function authed(method: string, url: string) {
  return server.inject({
    method: method as 'GET',
    url,
    headers: { authorization: `Bearer ${authToken}` },
  });
}

async function seedIoc(indicator: string, verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown' = 'clean') {
  const [record] = await db
    .insert(iocRecords)
    .values({
      indicator,
      type: 'ip',
      verdict,
      score: 0,
      sources: {},
      lastChecked: new Date(),
      expiresAt: new Date(Date.now() + 3_600_000),
    })
    .returning();
  return record;
}

describe('GET /api/v1/ioc', () => {
  it('requires authentication', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/ioc' });
    expect(res.statusCode).toBe(401);
  });

  it('returns empty list when no records exist', async () => {
    const res = await authed('GET', '/api/v1/ioc');
    expect(res.statusCode).toBe(200);
    expect(res.json().data).toEqual([]);
  });

  it('returns seeded IOC records', async () => {
    await seedIoc('10.0.0.1');
    await seedIoc('10.0.0.2');

    const res = await authed('GET', '/api/v1/ioc');
    expect(res.statusCode).toBe(200);
    expect(res.json().data.length).toBeGreaterThanOrEqual(2);
  });

  it('filters by verdict', async () => {
    await seedIoc('10.0.0.3', 'malicious');
    await seedIoc('10.0.0.4', 'clean');

    const res = await authed('GET', '/api/v1/ioc?verdict=malicious');
    const { data } = res.json();
    expect(data.every((r: { verdict: string }) => r.verdict === 'malicious')).toBe(true);
  });

  it('supports pagination', async () => {
    for (let i = 10; i < 15; i++) await seedIoc(`192.168.0.${i}`);

    const first = await authed('GET', '/api/v1/ioc?limit=2');
    const { nextCursor } = first.json();
    expect(nextCursor).not.toBeNull();

    const second = await authed('GET', `/api/v1/ioc?limit=2&cursor=${nextCursor}`);
    expect(second.statusCode).toBe(200);
    const page1ids = first.json().data.map((r: { id: string }) => r.id);
    expect(second.json().data.every((r: { id: string }) => !page1ids.includes(r.id))).toBe(true);
  });
});

describe('GET /api/v1/ioc/:indicator', () => {
  it('returns a cached record when a non-expired DB record exists', async () => {
    await seedIoc('5.5.5.5', 'suspicious');

    const res = await authed('GET', '/api/v1/ioc/5.5.5.5');
    expect(res.statusCode).toBe(200);
    expect(res.json().cached).toBe(true);
    expect(res.json().data.indicator).toBe('5.5.5.5');
  });

  it('calls enrichIoc when no DB record exists', async () => {
    const res = await authed('GET', '/api/v1/ioc/1.2.3.4');
    expect(res.statusCode).toBe(200);
    expect(res.json().cached).toBe(false);
  });
});
