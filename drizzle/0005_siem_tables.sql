-- SIEM: new enum types
CREATE TYPE "event_category" AS ENUM ('auth', 'network', 'threat', 'system', 'recon');
CREATE TYPE "incident_status" AS ENUM ('open', 'investigating', 'resolved');

--> statement-breakpoint

-- SIEM: log_events — normalized event store
CREATE TABLE IF NOT EXISTS "log_events" (
  "id"          uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "user_id"     uuid NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "source"      varchar(100) NOT NULL,
  "category"    "event_category" NOT NULL,
  "action"      varchar(200) NOT NULL,
  "severity"    "alert_severity" NOT NULL DEFAULT 'info',
  "source_ip"   inet,
  "target_ip"   inet,
  "target_port" integer,
  "message"     text,
  "raw_data"    jsonb,
  "created_at"  timestamp DEFAULT now() NOT NULL
);

--> statement-breakpoint

CREATE INDEX IF NOT EXISTS "le_user_id_idx"    ON "log_events" ("user_id");
CREATE INDEX IF NOT EXISTS "le_created_at_idx" ON "log_events" ("created_at");
CREATE INDEX IF NOT EXISTS "le_category_idx"   ON "log_events" ("user_id", "category");
CREATE INDEX IF NOT EXISTS "le_source_ip_idx"  ON "log_events" ("source_ip");

--> statement-breakpoint

-- SIEM: incidents — auto-created by correlation worker
CREATE TABLE IF NOT EXISTS "incidents" (
  "id"           uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "user_id"      uuid NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "title"        varchar(500) NOT NULL,
  "severity"     "alert_severity" NOT NULL,
  "status"       "incident_status" NOT NULL DEFAULT 'open',
  "rule_name"    varchar(200) NOT NULL,
  "event_count"  integer NOT NULL DEFAULT 1,
  "first_seen_at" timestamp NOT NULL,
  "last_seen_at"  timestamp NOT NULL,
  "resolved_at"   timestamp,
  "created_at"   timestamp DEFAULT now() NOT NULL,
  "updated_at"   timestamp DEFAULT now() NOT NULL
);

--> statement-breakpoint

CREATE INDEX IF NOT EXISTS "inc_user_id_idx"    ON "incidents" ("user_id");
CREATE INDEX IF NOT EXISTS "inc_status_idx"     ON "incidents" ("user_id", "status");
CREATE INDEX IF NOT EXISTS "inc_created_at_idx" ON "incidents" ("created_at");

--> statement-breakpoint

-- SIEM: correlation_rules — built-in detection rules
CREATE TABLE IF NOT EXISTS "correlation_rules" (
  "id"             uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "name"           varchar(200) NOT NULL UNIQUE,
  "description"    text NOT NULL,
  "category"       "event_category" NOT NULL,
  "severity"       "alert_severity" NOT NULL,
  "window_seconds" integer NOT NULL,
  "threshold"      integer NOT NULL,
  "group_by"       varchar(100),
  "conditions"     jsonb NOT NULL,
  "enabled"        boolean NOT NULL DEFAULT true,
  "created_at"     timestamp DEFAULT now() NOT NULL
);

--> statement-breakpoint

-- Seed the 4 built-in correlation rules
INSERT INTO "correlation_rules" ("name", "description", "category", "severity", "window_seconds", "threshold", "group_by", "conditions") VALUES
  (
    'brute_force',
    'Detects 5 or more failed login attempts from the same source IP within 2 minutes',
    'auth', 'high', 120, 5, 'source_ip',
    '{"action": "login_failed"}'
  ),
  (
    'port_scan',
    'Detects 10 or more unique destination ports probed from the same source IP within 5 minutes',
    'network', 'medium', 300, 10, 'source_ip',
    '{"action": "port_probe", "distinct": "target_port"}'
  ),
  (
    'ioc_spike',
    'Detects 3 or more IOC match events for the same source IP within 10 minutes',
    'threat', 'high', 600, 3, 'source_ip',
    '{"action": "ioc_match"}'
  ),
  (
    'credential_stuffing',
    'Detects 10 or more failed logins spread across 3 or more target IPs within 5 minutes',
    'auth', 'critical', 300, 10, NULL,
    '{"action": "login_failed", "distinct_targets": 3}'
  )
ON CONFLICT ("name") DO NOTHING;
