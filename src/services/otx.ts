import { env } from '../lib/env';

interface OtxPulse {
  name: string;
  tags: string[];
  malware_families: string[];
}

interface OtxGeneralResponse {
  pulse_info: { count: number; pulses: OtxPulse[] };
  validation: Array<{ name: string; source: string }>;
}

export interface OtxResult {
  pulseCount: number;
  malwareFamilies: string[];
  tags: string[];
}

type OtxIndicatorType = 'IPv4' | 'domain' | 'hostname' | 'URL';

export async function checkOtx(
  indicator: string,
  type: OtxIndicatorType,
): Promise<OtxResult | null> {
  if (!env.OTX_API_KEY) return null;

  const res = await fetch(
    `https://otx.alienvault.com/api/v1/indicators/${type}/${encodeURIComponent(indicator)}/general`,
    { headers: { 'X-OTX-API-KEY': env.OTX_API_KEY } },
  );

  if (!res.ok) return null;

  const body = (await res.json()) as OtxGeneralResponse;
  const pulses = body.pulse_info?.pulses ?? [];

  return {
    pulseCount: body.pulse_info?.count ?? 0,
    malwareFamilies: [...new Set(pulses.flatMap((p) => p.malware_families))],
    tags: [...new Set(pulses.flatMap((p) => p.tags))].slice(0, 20),
  };
}
