-- Add recon_sessions table for storing dashboard recon results

CREATE TYPE IF NOT EXISTS "recon_tool" AS ENUM (
  'ip', 'domain', 'subdomains', 'ssl', 'headers', 'portscan',
  'dns', 'reverseip', 'asn', 'whoishistory', 'certs', 'traceroute',
  'url', 'email', 'ioc', 'shodan', 'tech', 'waf', 'cors'
);

CREATE TABLE IF NOT EXISTS "recon_sessions" (
  "id"         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"    uuid NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "tool"       recon_tool NOT NULL,
  "target"     varchar(512) NOT NULL,
  "summary"    jsonb NOT NULL DEFAULT '{}',
  "results"    jsonb NOT NULL DEFAULT '{}',
  "tags"       jsonb NOT NULL DEFAULT '[]',
  "notes"      text,
  "created_at" timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS "rs_user_id_idx"    ON "recon_sessions" ("user_id");
CREATE INDEX IF NOT EXISTS "rs_tool_idx"       ON "recon_sessions" ("tool");
CREATE INDEX IF NOT EXISTS "rs_created_at_idx" ON "recon_sessions" ("created_at");
