-- Add refresh token and API key tables

CREATE TABLE IF NOT EXISTS "refresh_tokens" (
  "id"          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"     uuid NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "token_hash"  varchar(64) UNIQUE NOT NULL,
  "created_at"  timestamp DEFAULT now() NOT NULL,
  "expires_at"  timestamp NOT NULL,
  "revoked_at"  timestamp
);

CREATE TABLE IF NOT EXISTS "api_keys" (
  "id"           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "user_id"      uuid NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "key_hash"     varchar(64) UNIQUE NOT NULL,
  "name"         varchar(100) NOT NULL,
  "created_at"   timestamp DEFAULT now() NOT NULL,
  "last_used_at" timestamp,
  "revoked_at"   timestamp
);

CREATE INDEX IF NOT EXISTS "rt_user_id_idx"    ON "refresh_tokens" ("user_id");
CREATE INDEX IF NOT EXISTS "rt_expires_at_idx" ON "refresh_tokens" ("expires_at");
CREATE INDEX IF NOT EXISTS "ak_user_id_idx"    ON "api_keys" ("user_id");
