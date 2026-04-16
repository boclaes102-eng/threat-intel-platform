import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

export const registry = new Registry();
registry.setDefaultLabels({ service: 'threat-intel-api' });
collectDefaultMetrics({ register: registry });

export const httpRequestsTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status'] as const,
  registers: [registry],
});

export const httpRequestDuration = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request latency',
  labelNames: ['method', 'route', 'status'] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
  registers: [registry],
});

export const jobsTotal = new Counter({
  name: 'jobs_total',
  help: 'Background jobs processed',
  labelNames: ['queue', 'status'] as const,
  registers: [registry],
});

export const jobDuration = new Histogram({
  name: 'job_duration_seconds',
  help: 'Background job duration',
  labelNames: ['queue'] as const,
  buckets: [0.1, 0.5, 1, 5, 10, 30, 60, 120, 300],
  registers: [registry],
});

export const cacheHitsTotal = new Counter({
  name: 'cache_hits_total',
  help: 'Cache hits',
  labelNames: ['key_type'] as const,
  registers: [registry],
});

export const cacheMissesTotal = new Counter({
  name: 'cache_misses_total',
  help: 'Cache misses',
  labelNames: ['key_type'] as const,
  registers: [registry],
});

export const activeAssetsGauge = new Gauge({
  name: 'active_assets_total',
  help: 'Active monitored assets',
  registers: [registry],
});

export const openAlertsGauge = new Gauge({
  name: 'open_alerts_total',
  help: 'Unread alerts by severity',
  labelNames: ['severity'] as const,
  registers: [registry],
});
