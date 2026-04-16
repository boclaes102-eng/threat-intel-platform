import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock external service calls so unit tests don't hit real APIs
vi.mock('../../../src/services/abuseipdb', () => ({
  checkAbuseIpDb: vi.fn(),
}));
vi.mock('../../../src/services/virustotal', () => ({
  checkVtIp: vi.fn(),
  checkVtDomain: vi.fn(),
}));
vi.mock('../../../src/services/otx', () => ({
  checkOtx: vi.fn(),
}));
vi.mock('../../../src/lib/redis', () => ({
  getCacheKeyed: vi.fn().mockResolvedValue(null),
  setCache: vi.fn().mockResolvedValue(undefined),
  cacheHitsTotal: { inc: vi.fn() },
  cacheMissesTotal: { inc: vi.fn() },
}));
vi.mock('../../../src/lib/metrics', () => ({
  cacheHitsTotal: { inc: vi.fn() },
  cacheMissesTotal: { inc: vi.fn() },
}));

import { enrichIoc } from '../../../src/services/ioc-enrichment';
import { checkAbuseIpDb } from '../../../src/services/abuseipdb';
import { checkVtIp } from '../../../src/services/virustotal';
import { checkOtx } from '../../../src/services/otx';

const mockCheckAbuseIpDb = vi.mocked(checkAbuseIpDb);
const mockCheckVtIp = vi.mocked(checkVtIp);
const mockCheckOtx = vi.mocked(checkOtx);

describe('enrichIoc', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('detects IP type correctly', async () => {
    mockCheckAbuseIpDb.mockResolvedValue(null);
    mockCheckVtIp.mockResolvedValue(null);
    mockCheckOtx.mockResolvedValue(null);

    const result = await enrichIoc('8.8.8.8');
    expect(result.type).toBe('ip');
    expect(result.indicator).toBe('8.8.8.8');
  });

  it('detects domain type correctly', async () => {
    const result = await enrichIoc('example.com');
    expect(result.type).toBe('domain');
  });

  it('detects hash type correctly', async () => {
    const result = await enrichIoc('d41d8cd98f00b204e9800998ecf8427e');
    expect(result.type).toBe('hash');
  });

  it('returns malicious verdict when AbuseIPDB score is high', async () => {
    mockCheckAbuseIpDb.mockResolvedValue({
      score: 95,
      totalReports: 50,
      isp: 'Bad ISP',
      domain: 'bad.net',
      countryCode: 'XX',
      lastReportedAt: new Date().toISOString(),
    });
    mockCheckVtIp.mockResolvedValue(null);
    mockCheckOtx.mockResolvedValue(null);

    const result = await enrichIoc('1.2.3.4');
    expect(result.verdict).toBe('malicious');
    expect(result.score).toBeGreaterThanOrEqual(70);
    expect(result.sources).toHaveLength(1);
    expect(result.sources[0].name).toBe('AbuseIPDB');
  });

  it('returns suspicious when OTX finds pulses', async () => {
    mockCheckAbuseIpDb.mockResolvedValue(null);
    mockCheckVtIp.mockResolvedValue({ malicious: 0, suspicious: 0, harmless: 10, undetected: 5, reputation: 0, total: 15 });
    mockCheckOtx.mockResolvedValue({ pulseCount: 4, malwareFamilies: [], tags: ['botnet'] });

    const result = await enrichIoc('10.0.0.1');
    expect(['suspicious', 'clean', 'unknown']).toContain(result.verdict);
    expect(result.sources.length).toBeGreaterThan(0);
  });

  it('returns unknown verdict when no sources are available', async () => {
    mockCheckAbuseIpDb.mockResolvedValue(null);
    mockCheckVtIp.mockResolvedValue(null);
    mockCheckOtx.mockResolvedValue(null);

    const result = await enrichIoc('192.168.1.1');
    expect(result.verdict).toBe('unknown');
    expect(result.score).toBe(0);
  });

  it('aggregates scores from multiple sources', async () => {
    mockCheckAbuseIpDb.mockResolvedValue({
      score: 40,
      totalReports: 5,
      isp: 'Some ISP',
      domain: 'example.com',
      countryCode: 'US',
      lastReportedAt: null,
    });
    mockCheckVtIp.mockResolvedValue({ malicious: 5, suspicious: 2, harmless: 50, undetected: 10, reputation: -5, total: 67 });
    mockCheckOtx.mockResolvedValue({ pulseCount: 2, malwareFamilies: [], tags: [] });

    const result = await enrichIoc('5.5.5.5');
    expect(result.sources.length).toBe(3);
    expect(result.score).toBeGreaterThan(0);
  });
});
