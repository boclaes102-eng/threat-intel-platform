import { env } from '../lib/env';
import { logger } from '../lib/logger';

const BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

export interface NvdCveItem {
  cve: {
    id: string;
    published: string;
    lastModified: string;
    descriptions: Array<{ lang: string; value: string }>;
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData: { baseScore: number; baseSeverity: string; vectorString: string };
      }>;
      cvssMetricV30?: Array<{
        cvssData: { baseScore: number; baseSeverity: string; vectorString: string };
      }>;
    };
    references: Array<{ url: string }>;
    configurations?: Array<{
      nodes: Array<{
        cpeMatch: Array<{ criteria: string; vulnerable: boolean }>;
      }>;
    }>;
  };
}

interface NvdResponse {
  totalResults: number;
  vulnerabilities: NvdCveItem[];
}

export async function fetchRecentCves(
  daysBack = 7,
  startIndex = 0,
  resultsPerPage = 100,
): Promise<NvdResponse> {
  const pubEndDate = new Date().toISOString();
  const pubStartDate = new Date(Date.now() - daysBack * 86_400_000).toISOString();

  const params = new URLSearchParams({
    pubStartDate,
    pubEndDate,
    startIndex: String(startIndex),
    resultsPerPage: String(resultsPerPage),
  });

  const headers: HeadersInit = { 'User-Agent': 'threat-intel-platform/1.0' };
  if (env.NVD_API_KEY) headers['apiKey'] = env.NVD_API_KEY;

  const res = await fetch(`${BASE_URL}?${params}`, { headers });

  if (!res.ok) {
    const text = await res.text();
    logger.warn({ status: res.status, body: text }, 'NVD API error');
    throw new Error(`NVD API returned ${res.status}`);
  }

  return res.json() as Promise<NvdResponse>;
}

export function extractCvssFromItem(item: NvdCveItem) {
  const metrics = item.cve.metrics;
  const v31 = metrics?.cvssMetricV31?.[0]?.cvssData;
  const v30 = metrics?.cvssMetricV30?.[0]?.cvssData;
  const best = v31 ?? v30;
  return best
    ? { score: best.baseScore, severity: best.baseSeverity.toLowerCase(), vector: best.vectorString }
    : null;
}

export function extractAffectedProducts(item: NvdCveItem): string[] {
  const products: string[] = [];
  for (const config of item.cve.configurations ?? []) {
    for (const node of config.nodes) {
      for (const cpe of node.cpeMatch) {
        if (cpe.vulnerable) products.push(cpe.criteria);
      }
    }
  }
  return [...new Set(products)];
}
