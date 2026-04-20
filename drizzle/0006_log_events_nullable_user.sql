-- Allow log_events and incidents to be created without a user_id (external sources like personal website)
ALTER TABLE "log_events" ALTER COLUMN "user_id" DROP NOT NULL;
ALTER TABLE "incidents"  ALTER COLUMN "user_id" DROP NOT NULL;
