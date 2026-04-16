import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../../src/api/server';
import { db } from '../../../src/db';
import { alerts, assets } from '../../../src/db/schema';

vi.mock('../../../src/workers/queues', () => ({
  iocScanQueue: { add: vi.fn().mockResolvedValue(undefined) },
  assetScanQueue: { add: vi.fn().mockResolvedValue(undefined) },
  cveFeedQueue: { add: vi.fn().mockResolvedValue(undefined) },
  scheduleRecurringJobs: vi.fn().mockResolvedValue(undefined),
}));

let server: FastifyInstance;
let authToken: string;
let userId: string;

beforeAll(async () => {
  server = await buildServer();
  await server.ready();

  const reg = await server.inject({
    method: 'POST',
    url: '/api/v1/auth/register',
    payload: { email: 'alerts-test@example.com', password: 'password123' },
  });
  const body = reg.json();
  authToken = body.accessToken;
  userId = body.user.id;
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

async function seedAlert(overrides: Partial<typeof alerts.$inferInsert> = {}) {
  const [alert] = await db
    .insert(alerts)
    .values({
      userId,
      type: 'ioc_match',
      severity: 'high',
      title: 'Test alert',
      details: { test: true },
      ...overrides,
    })
    .returning();
  return alert;
}

describe('GET /api/v1/alerts', () => {
  it('returns alerts for the authenticated user', async () => {
    await seedAlert({ title: 'Alert 1' });
    await seedAlert({ title: 'Alert 2' });

    const res = await authed('GET', '/api/v1/alerts');
    expect(res.statusCode).toBe(200);
    expect(res.json().data.length).toBeGreaterThanOrEqual(2);
  });

  it('filters by severity', async () => {
    await seedAlert({ severity: 'critical', title: 'Critical alert' });
    await seedAlert({ severity: 'low', title: 'Low alert' });

    const res = await authed('GET', '/api/v1/alerts?severity=critical');
    const { data } = res.json();
    expect(data.every((a: { severity: string }) => a.severity === 'critical')).toBe(true);
  });

  it('filters unread alerts', async () => {
    await seedAlert({ title: 'Unread' });
    const readAlert = await seedAlert({ title: 'Read' });
    await authed('POST', `/api/v1/alerts/${readAlert.id}/read`);

    const res = await authed('GET', '/api/v1/alerts?unread=true');
    const { data } = res.json();
    expect(data.some((a: { title: string }) => a.title === 'Read')).toBe(false);
    expect(data.some((a: { title: string }) => a.title === 'Unread')).toBe(true);
  });

  it('supports cursor pagination', async () => {
    for (let i = 0; i < 5; i++) await seedAlert({ title: `Page alert ${i}` });

    const first = await authed('GET', '/api/v1/alerts?limit=2');
    const { nextCursor } = first.json();
    expect(nextCursor).not.toBeNull();

    const second = await authed('GET', `/api/v1/alerts?limit=2&cursor=${nextCursor}`);
    expect(second.statusCode).toBe(200);
    const page2data = second.json().data;
    const page1ids = first.json().data.map((a: { id: string }) => a.id);
    expect(page2data.every((a: { id: string }) => !page1ids.includes(a.id))).toBe(true);
  });
});

describe('POST /api/v1/alerts/:id/read', () => {
  it('marks an alert as read', async () => {
    const alert = await seedAlert();
    const res = await authed('POST', `/api/v1/alerts/${alert.id}/read`);
    expect(res.statusCode).toBe(200);

    const listRes = await authed('GET', `/api/v1/alerts?unread=true`);
    const unread = listRes.json().data;
    expect(unread.some((a: { id: string }) => a.id === alert.id)).toBe(false);
  });

  it('returns 404 for another user\'s alert', async () => {
    const alert = await seedAlert();
    const reg2 = await server.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { email: 'other-alerts@example.com', password: 'password123' },
    });
    const token2 = reg2.json().accessToken;

    const res = await server.inject({
      method: 'POST',
      url: `/api/v1/alerts/${alert.id}/read`,
      headers: { authorization: `Bearer ${token2}` },
    });
    expect(res.statusCode).toBe(404);
  });
});

describe('DELETE /api/v1/alerts/:id', () => {
  it('deletes an alert', async () => {
    const alert = await seedAlert();
    const res = await authed('DELETE', `/api/v1/alerts/${alert.id}`);
    expect(res.statusCode).toBe(204);
  });
});
