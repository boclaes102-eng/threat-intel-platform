import { checkAbuseIpDb } from './abuseipdb';
import { checkVtIp, checkVtDomain } from './virustotal';
import { checkOtx } from './otx';
import { getCacheKeyed, setCache } from '../lib/redis';
import { cacheHitsTotal, cacheMissesTotal } from '../lib/metrics';
import { env } from '../lib/env';
import type { IocSource } from '../db/schema/ioc-records';

export type IocType = 'ip' | 'domain' | 'url' | 'hash';
export type IocVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

export interface EnrichedIoc {
  indicator: string;
  type: IocType;
  verdict: IocVerdict;
  score: number;
  sources: IocSource[];
}

function detectType(indicator: string): IocType {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(indicator)) return 'ip';
  if (/^[0-9a-fA-F]{32,64}$/.test(indicator)) return 'hash';
  if (/^https?:\/\//.test(indicator)) return 'url';
  return 'domain';
}

function computeVerdict(score: number): IocVerdict {
  if (score >= 70) return 'malicious';
  if (score >= 30) return 'suspicious';
  if (score > 0) return 'clean';
  return 'unknown';
}

export async function enrichIoc(indicator: string): Promise<EnrichedIoc> {
  const cacheKey = `ioc:${indicator}`;

  const cached = await getCacheKeyed<EnrichedIoc>(cacheKey);
  if (cached) {
    cacheHitsTotal.inc({ key_type: 'ioc' });
    return cached;
  }
  cacheMissesTotal.inc({ key_type: 'ioc' });

  const type = detectType(indicator);
  const sources: IocSource[] = [];
  let totalScore = 0;
  let sourceCount = 0;

  if (type === 'ip') {
    const [abuse, vt, otx] = await Promise.allSettled([
      checkAbuseIpDb(indicator),
      checkVtIp(indicator),
      checkOtx(indicator, 'IPv4'),
    ]);

    if (abuse.status === 'fulfilled' && abuse.value) {
      const s = abuse.value.score;
      sources.push({ name: 'AbuseIPDB', found: s > 0, verdict: s > 50 ? 'malicious' : 'clean', score: s });
      totalScore += s;
      sourceCount++;
    }

    if (vt.status === 'fulfilled' && vt.value) {
      const vtScore = vt.value.total > 0
        ? Math.round(((vt.value.malicious + vt.value.suspicious * 0.5) / vt.value.total) * 100)
        : 0;
      sources.push({ name: 'VirusTotal', found: vt.value.malicious > 0, verdict: vt.value.malicious > 0 ? 'malicious' : 'clean', score: vtScore });
      totalScore += vtScore;
      sourceCount++;
    }

    if (otx.status === 'fulfilled' && otx.value) {
      const otxScore = Math.min(otx.value.pulseCount * 10, 100);
      sources.push({ name: 'AlienVault OTX', found: otx.value.pulseCount > 0, verdict: otx.value.pulseCount > 0 ? 'suspicious' : 'clean', score: otxScore });
      totalScore += otxScore;
      sourceCount++;
    }
  }

  if (type === 'domain') {
    const [vt, otx] = await Promise.allSettled([
      checkVtDomain(indicator),
      checkOtx(indicator, 'domain'),
    ]);

    if (vt.status === 'fulfilled' && vt.value) {
      const vtScore = vt.value.total > 0
        ? Math.round(((vt.value.malicious + vt.value.suspicious * 0.5) / vt.value.total) * 100)
        : 0;
      sources.push({ name: 'VirusTotal', found: vt.value.malicious > 0, verdict: vt.value.malicious > 0 ? 'malicious' : 'clean', score: vtScore });
      totalScore += vtScore;
      sourceCount++;
    }

    if (otx.status === 'fulfilled' && otx.value) {
      const otxScore = Math.min(otx.value.pulseCount * 10, 100);
      sources.push({ name: 'AlienVault OTX', found: otx.value.pulseCount > 0, verdict: otx.value.pulseCount > 0 ? 'suspicious' : 'clean', score: otxScore });
      totalScore += otxScore;
      sourceCount++;
    }
  }

  const score = sourceCount > 0 ? Math.round(totalScore / sourceCount) : 0;
  const result: EnrichedIoc = {
    indicator,
    type,
    verdict: computeVerdict(score),
    score,
    sources,
  };

  await setCache(cacheKey, result, env.IOC_CACHE_TTL);
  return result;
}
