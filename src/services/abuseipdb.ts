import { env } from '../lib/env';

interface AbuseIpDbResponse {
  data: {
    ipAddress: string;
    isPublic: boolean;
    abuseConfidenceScore: number;
    countryCode: string;
    totalReports: number;
    lastReportedAt: string | null;
    isp: string;
    domain: string;
  };
}

export interface AbuseIpResult {
  score: number;
  totalReports: number;
  isp: string;
  domain: string;
  countryCode: string;
  lastReportedAt: string | null;
}

export async function checkAbuseIpDb(ip: string): Promise<AbuseIpResult | null> {
  if (!env.ABUSEIPDB_API_KEY) return null;

  const res = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
    {
      headers: {
        Key: env.ABUSEIPDB_API_KEY,
        Accept: 'application/json',
      },
    },
  );

  if (!res.ok) return null;

  const body = (await res.json()) as AbuseIpDbResponse;
  return {
    score: body.data.abuseConfidenceScore,
    totalReports: body.data.totalReports,
    isp: body.data.isp,
    domain: body.data.domain,
    countryCode: body.data.countryCode,
    lastReportedAt: body.data.lastReportedAt,
  };
}
