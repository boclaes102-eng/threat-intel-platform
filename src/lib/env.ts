import { z } from 'zod';
import 'dotenv/config';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(3001),
  HOST: z.string().default('0.0.0.0'),
  LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),

  DATABASE_URL: z.string().min(1),
  DB_POOL_MAX: z.coerce.number().default(20),
  REDIS_URL: z.string().default('redis://localhost:6379'),

  JWT_SECRET: z.string().min(32),
  ACCESS_TOKEN_EXPIRY: z.string().default('15m'),
  REFRESH_TOKEN_EXPIRY_DAYS: z.coerce.number().default(30),

  CORS_ORIGIN: z.string().default('http://localhost:3000'),

  IOC_CACHE_TTL: z.coerce.number().default(3600),
  CVE_CACHE_TTL: z.coerce.number().default(21600),

  SIEM_WEBHOOK_SECRET: z.string().optional(),

  ABUSEIPDB_API_KEY: z.string().optional(),
  VT_API_KEY: z.string().optional(),
  NVD_API_KEY: z.string().optional(),
  OTX_API_KEY: z.string().optional(),

  // Email alerts (all optional — notifications are skipped if not configured)
  SMTP_HOST:     z.string().optional(),
  SMTP_PORT:     z.coerce.number().default(587),
  SMTP_USER:     z.string().optional(),
  SMTP_PASS:     z.string().optional(),
  SMTP_FROM:     z.string().default('alerts@threat-intel.local'),
  ALERT_EMAIL:   z.string().email().optional(),
  DASHBOARD_URL: z.string().default('https://online-cyber-dashboard.vercel.app'),
});

const result = schema.safeParse(process.env);

if (!result.success) {
  console.error('❌ Invalid environment variables:');
  console.error(result.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = result.data;
export type Env = typeof env;
