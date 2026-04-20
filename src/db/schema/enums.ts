import { pgEnum } from 'drizzle-orm/pg-core';

export const assetTypeEnum = pgEnum('asset_type', ['ip', 'domain', 'cidr', 'url']);
export const severityEnum = pgEnum('severity', ['critical', 'high', 'medium', 'low', 'none']);
export const vulnStatusEnum = pgEnum('vuln_status', ['open', 'acknowledged', 'remediated', 'false_positive']);
export const alertTypeEnum = pgEnum('alert_type', ['vulnerability', 'ioc_match', 'scan_complete', 'feed_update']);
export const alertSeverityEnum = pgEnum('alert_severity', ['critical', 'high', 'medium', 'low', 'info']);
export const iocTypeEnum = pgEnum('ioc_type', ['ip', 'domain', 'url', 'hash']);
export const iocVerdictEnum = pgEnum('ioc_verdict', ['malicious', 'suspicious', 'clean', 'unknown']);
export const feedStatusEnum = pgEnum('feed_status', ['running', 'completed', 'failed']);
export const reconToolEnum = pgEnum('recon_tool', [
  'ip', 'domain', 'subdomains', 'ssl', 'headers', 'portscan',
  'dns', 'reverseip', 'asn', 'whoishistory', 'certs', 'traceroute',
  'url', 'email', 'ioc', 'shodan', 'tech', 'waf', 'cors',
]);

export const eventCategoryEnum = pgEnum('event_category', ['auth', 'network', 'threat', 'system', 'recon']);
export const incidentStatusEnum = pgEnum('incident_status', ['open', 'investigating', 'resolved']);
