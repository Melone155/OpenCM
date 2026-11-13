ALTER TABLE "users" ADD COLUMN "mfa_secret_enc" text;
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "mfa_enabled" boolean DEFAULT false NOT NULL;
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "mfa_recovery_hashes" text[] DEFAULT '{}' NOT NULL;
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "mfa_last_counter" bigint;
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "ldap_dn" text;
--> statement-breakpoint
ALTER TABLE "groups" ADD COLUMN "ldap_group" text;
--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "mfa_pending" boolean DEFAULT false NOT NULL;
--> statement-breakpoint
CREATE INDEX "api_tokens_user_idx" ON "api_tokens" USING btree ("user_id");
--> statement-breakpoint
CREATE TABLE "settings" (
	"key" text PRIMARY KEY NOT NULL,
	"value" jsonb NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_by" uuid REFERENCES "users"("id") ON DELETE set null
);
--> statement-breakpoint
CREATE TABLE "approval_requests" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"action" text NOT NULL,
	"summary" text NOT NULL,
	"payload" jsonb NOT NULL,
	"device_count" integer DEFAULT 0 NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"requested_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"requested_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"decided_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"decided_at" timestamp with time zone,
	"reason" text,
	"result" jsonb
);
--> statement-breakpoint
CREATE INDEX "approval_requests_status_idx" ON "approval_requests" USING btree ("status","requested_at");
