import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../../../src/api/server';
import { db } from '../../../src/db';
import { vulnerabilities, assets, assetVulnerabilities } from '../../../src/db/schema';

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
    payload: { email: 'vulns-test@example.com', password: 'password123' },
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

async function seedVuln(cveId: string) {
  const [vuln] = await db
    .insert(vulnerabilities)
    .values({
      cveId,
      description: `Description for ${cveId}`,
      severity: 'high',
      publishedAt: new Date(),
    })
    .returning();
  return vuln;
}

async function seedAsset(value: string) {
  const [asset] = await db
    .insert(assets)
    .values({ userId, type: 'domain', value })
    .returning();
  return asset;
}

describe('GET /api/v1/vulnerabilities', () => {
  it('requires authentication', async () => {
    const res = await server.inject({ method: 'GET', url: '/api/v1/vulnerabilities' });
    expect(res.statusCode).toBe(401);
  });

  it('returns an empty list when no CVEs exist', async () => {
    const res = await authed('GET', '/api/v1/vulnerabilities');
    expect(res.statusCode).toBe(200);
    expect(res.json().data).toEqual([]);
  });

  it('returns seeded CVEs', async () => {
    await seedVuln('CVE-2024-0001');
    await seedVuln('CVE-2024-0002');

    const res = await authed('GET', '/api/v1/vulnerabilities');
    expect(res.statusCode).toBe(200);
    expect(res.json().data.length).toBeGreaterThanOrEqual(2);
  });

  it('filters by severity', async () => {
    await db.insert(vulnerabilities).values({
      cveId: 'CVE-2024-CRIT',
      description: 'Critical vuln',
      severity: 'critical',
      publishedAt: new Date(),
    });

    const res = await authed('GET', '/api/v1/vulnerabilities?severity=critical');
    const { data } = res.json();
    expect(data.every((v: { severity: string }) => v.severity === 'critical')).toBe(true);
  });

  it('filters by search term', async () => {
    await seedVuln('CVE-2024-SEARCH');

    const res = await authed('GET', '/api/v1/vulnerabilities?search=SEARCH');
    const { data } = res.json();
    expect(data.some((v: { cveId: string }) => v.cveId === 'CVE-2024-SEARCH')).toBe(true);
  });

  it('returns 404 when scoping to a non-existent asset', async () => {
    const fakeId = '00000000-0000-0000-0000-000000000000';
    const res = await authed('GET', `/api/v1/vulnerabilities?assetId=${fakeId}`);
    expect(res.statusCode).toBe(404);
  });

  it('returns asset-scoped vulnerabilities', async () => {
    const asset = await seedAsset('scoped-asset.com');
    const vuln = await seedVuln('CVE-2024-SCOPED');
    await db.insert(assetVulnerabilities).values({ assetId: asset.id, vulnerabilityId: vuln.id });

    const res = await authed('GET', `/api/v1/vulnerabilities?assetId=${asset.id}`);
    expect(res.statusCode).toBe(200);
    const { data } = res.json();
    expect(data.some((v: { cveId: string }) => v.cveId === 'CVE-2024-SCOPED')).toBe(true);
  });
});

describe('GET /api/v1/vulnerabilities/:cveId', () => {
  it('returns a CVE by ID', async () => {
    await seedVuln('CVE-2024-BYID');

    const res = await authed('GET', '/api/v1/vulnerabilities/CVE-2024-BYID');
    expect(res.statusCode).toBe(200);
    expect(res.json().data.cveId).toBe('CVE-2024-BYID');
  });

  it('is case-insensitive for cveId', async () => {
    await seedVuln('CVE-2024-CASE');
    const res = await authed('GET', '/api/v1/vulnerabilities/cve-2024-case');
    expect(res.statusCode).toBe(200);
  });

  it('returns 404 for unknown CVE', async () => {
    const res = await authed('GET', '/api/v1/vulnerabilities/CVE-9999-9999');
    expect(res.statusCode).toBe(404);
  });
});

describe('PATCH /api/v1/assets/:assetId/vulnerabilities/:cveId', () => {
  it('updates vulnerability status on an asset', async () => {
    const asset = await seedAsset('patch-asset.com');
    const vuln = await seedVuln('CVE-2024-PATCH');
    await db.insert(assetVulnerabilities).values({ assetId: asset.id, vulnerabilityId: vuln.id });

    const res = await authed('PATCH', `/api/v1/assets/${asset.id}/vulnerabilities/CVE-2024-PATCH`, {
      status: 'acknowledged',
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().success).toBe(true);
  });

  it('returns 404 for unknown asset', async () => {
    await seedVuln('CVE-2024-NOASSET');
    const fakeId = '00000000-0000-0000-0000-000000000000';
    const res = await authed('PATCH', `/api/v1/assets/${fakeId}/vulnerabilities/CVE-2024-NOASSET`, {
      status: 'remediated',
    });
    expect(res.statusCode).toBe(404);
  });

  it('returns 404 for unknown CVE', async () => {
    const asset = await seedAsset('nocve-asset.com');
    const res = await authed('PATCH', `/api/v1/assets/${asset.id}/vulnerabilities/CVE-9999-0000`, {
      status: 'remediated',
    });
    expect(res.statusCode).toBe(404);
  });
});
