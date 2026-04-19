-- Fix alerts.asset_id FK: drop whatever the auto-named SET NULL constraint is, add CASCADE
DO $$
DECLARE
  c TEXT;
BEGIN
  SELECT conname INTO c
  FROM pg_constraint
  WHERE conrelid = 'alerts'::regclass
    AND contype = 'f'
    AND confrelid = 'assets'::regclass;
  IF c IS NOT NULL THEN
    EXECUTE 'ALTER TABLE alerts DROP CONSTRAINT ' || quote_ident(c);
  END IF;
END $$;

ALTER TABLE "alerts" ADD CONSTRAINT "alerts_asset_id_assets_id_fk"
  FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE;
