-- Drop ALL FK constraints from alerts.asset_id → assets.id (catches any auto-named ones)
-- then add a single CASCADE constraint
DO $$
DECLARE
  c TEXT;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'alerts'::regclass
      AND contype = 'f'
      AND confrelid = 'assets'::regclass
  LOOP
    EXECUTE 'ALTER TABLE alerts DROP CONSTRAINT ' || quote_ident(c);
  END LOOP;
END $$;

ALTER TABLE "alerts" ADD CONSTRAINT "alerts_asset_id_cascade_fk"
  FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE;
