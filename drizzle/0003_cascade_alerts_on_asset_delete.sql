-- Change alerts.asset_id FK from SET NULL to CASCADE so alerts are deleted with their asset
ALTER TABLE "alerts" DROP CONSTRAINT IF EXISTS "alerts_asset_id_assets_id_fk";
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_asset_id_assets_id_fk"
  FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE CASCADE;
