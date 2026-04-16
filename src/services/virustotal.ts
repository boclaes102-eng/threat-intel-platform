import { env } from '../lib/env';

interface VtAttributes {
  last_analysis_stats: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
  };
  reputation: number;
  last_analysis_date?: number;
}

export interface VtResult {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  reputation: number;
  total: number;
}

async function vtGet(path: string): Promise<VtAttributes | null> {
  if (!env.VT_API_KEY) return null;

  const res = await fetch(`https://www.virustotal.com/api/v3/${path}`, {
    headers: { 'x-apikey': env.VT_API_KEY },
  });

  if (!res.ok) return null;

  const body = (await res.json()) as { data: { attributes: VtAttributes } };
  return body.data.attributes;
}

export async function checkVtIp(ip: string): Promise<VtResult | null> {
  const attrs = await vtGet(`ip_addresses/${encodeURIComponent(ip)}`);
  return attrs ? toVtResult(attrs) : null;
}

export async function checkVtDomain(domain: string): Promise<VtResult | null> {
  const attrs = await vtGet(`domains/${encodeURIComponent(domain)}`);
  return attrs ? toVtResult(attrs) : null;
}

function toVtResult(attrs: VtAttributes): VtResult {
  const stats = attrs.last_analysis_stats;
  return {
    malicious: stats.malicious,
    suspicious: stats.suspicious,
    harmless: stats.harmless,
    undetected: stats.undetected,
    reputation: attrs.reputation,
    total: stats.malicious + stats.suspicious + stats.harmless + stats.undetected,
  };
}
