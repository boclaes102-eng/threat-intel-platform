import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../../src/api/server';

// Don't actually enqueue jobs in tests
vi.mock('../../../src/workers/queues', () => ({
  iocScanQueue: { add: vi.fn().mockResolvedValue(undefined) },
  assetScanQueue: { add: vi.fn().mockResolvedValue(undefined) },
  cveFeedQueue: { add: vi.fn().mockResolvedValue(undefined) },
  scheduleRecurringJobs: vi.fn().mockResolvedValue(undefined),
}));

let server: FastifyInstance;
let authToken: string;

beforeAll(async () => {
  server = await buildServer();
  await server.ready();
});

beforeEach(async () => {
  const reg = await server.inject({
    method: 'POST',
    url: '/api/v1/auth/register',
    payload: { email: 'assets-test@example.com', password: 'password123' },
  });
  authToken = reg.json().accessToken;
});

afterAll(async () => {
  await server.close();
});

async function authed(method: string, url: string, payload?: unknown) {
  return server.inject({
    method: method as 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url,
    headers: { authorization: `Bearer ${authToken}` },
    payload,
  });
}

describe('POST /api/v1/assets', () => {
  it('creates a domain asset', async () => {
    const res = await authed('POST', '/api/v1/assets', {
      type: 'domain',
      value: 'example.com',
      label: 'Test domain',
      tags: ['production'],
    });

    expect(res.statusCode).toBe(201);
    const { data } = res.json();
    expect(data.value).toBe('example.com');
    expect(data.type).toBe('domain');
    expect(data.label).toBe('Test domain');
  });

  it('creates an IP asset', async () => {
    const res = await authed('POST', '/api/v1/assets', { type: 'ip', value: '8.8.8.8' });
    expect(res.statusCode).toBe(201);
    expect(res.json().data.type).toBe('ip');
  });

  it('returns 409 for duplicate asset value', async () => {
    await authed('POST', '/api/v1/assets', { type: 'domain', value: 'duplicate.com' });
    const res = await authed('POST', '/api/v1/assets', { type: 'domain', value: 'duplicate.com' });
    expect(res.statusCode).toBe(409);
  });

  it('returns 400 for invalid asset type', async () => {
    const res = await authed('POST', '/api/v1/assets', { type: 'ftp', value: 'test.com' });
    expect(res.statusCode).toBe(400);
  });

  it('returns 401 without token', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/api/v1/assets',
      payload: { type: 'domain', value: 'test.com' },
    });
    expect(res.statusCode).toBe(401);
  });
});

describe('GET /api/v1/assets', () => {
  it('returns paginated assets for the authenticated user', async () => {
    await authed('POST', '/api/v1/assets', { type: 'domain', value: 'page1.com' });
    await authed('POST', '/api/v1/assets', { type: 'domain', value: 'page2.com' });

    const res = await authed('GET', '/api/v1/assets?limit=1');
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.data).toHaveLength(1);
    expect(body.nextCursor).not.toBeNull();
  });

  it('filters by type', async () => {
    await authed('POST', '/api/v1/assets', { type: 'ip', value: '1.2.3.4' });

    const res = await authed('GET', '/api/v1/assets?type=ip');
    const { data } = res.json();
    expect(data.every((a: { type: string }) => a.type === 'ip')).toBe(true);
  });

  it('does not return another user\'s assets', async () => {
    const reg2 = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'other@example.com', password: 'password123' },
    });
    const token2 = reg2.json().accessToken;

    await server.inject({
      method: 'POST',
      url: '/api/v1/assets',
      headers: { authorization: `Bearer ${token2}` },
      payload: { type: 'domain', value: 'secret.com' },
    });

    const res = await authed('GET', '/api/v1/assets');
    const values = res.json().data.map((a: { value: string }) => a.value);
    expect(values).not.toContain('secret.com');
  });
});

describe('PATCH /api/v1/assets/:id', () => {
  it('updates asset label and tags', async () => {
    const create = await authed('POST', '/api/v1/assets', { type: 'domain', value: 'update-me.com' });
    const id = create.json().data.id;

    const res = await authed('PATCH', `/api/v1/assets/${id}`, {
      label: 'Updated label',
      tags: ['tag1', 'tag2'],
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().data.label).toBe('Updated label');
  });
});

describe('DELETE /api/v1/assets/:id', () => {
  it('deletes an asset', async () => {
    const create = await authed('POST', '/api/v1/assets', { type: 'domain', value: 'delete-me.com' });
    const id = create.json().data.id;

    const del = await authed('DELETE', `/api/v1/assets/${id}`);
    expect(del.statusCode).toBe(204);

    const get = await authed('GET', `/api/v1/assets/${id}`);
    expect(get.statusCode).toBe(404);
  });
});
