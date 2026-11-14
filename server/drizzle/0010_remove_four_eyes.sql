-- Four-eyes approvals removed: deployments waiting for approval are cancelled,
-- the approval requests and the obsolete permissions disappear.
UPDATE "deployments" SET "status" = 'cancelled', "finished_at" = now(), "paused_reason" = 'Vier-Augen-Freigabe entfernt'
  WHERE "status" = 'pending_approval';--> statement-breakpoint
ALTER TABLE "deployments" DROP COLUMN "approval_id";--> statement-breakpoint
DROP TABLE "approval_requests";--> statement-breakpoint
UPDATE "roles" SET "permissions" = array_remove(array_remove("permissions", 'jobs:approve'), 'patches:approve');
