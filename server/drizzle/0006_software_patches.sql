-- integrity seal (HMAC with PKI_DIR/integrity.key) – existing versions are sealed at server start
ALTER TABLE "script_versions" ADD COLUMN "seal" text;
--> statement-breakpoint
CREATE TABLE "package_files" (
	"sha256" text PRIMARY KEY NOT NULL,
	"size_bytes" bigint NOT NULL,
	"original_name" text NOT NULL,
	"uploaded_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "packages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL UNIQUE,
	"publisher" text DEFAULT '' NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"platform" text NOT NULL,
	"created_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "package_versions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"package_id" uuid NOT NULL REFERENCES "packages"("id") ON DELETE cascade,
	"version" text NOT NULL,
	"type" text NOT NULL,
	"file_sha256" text REFERENCES "package_files"("sha256") ON DELETE restrict,
	"file_name" text,
	"package_ref" text,
	"install_args" text DEFAULT '' NOT NULL,
	"install_command" text DEFAULT '' NOT NULL,
	"uninstall_command" text DEFAULT '' NOT NULL,
	"product_code" text,
	"detection" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"success_codes" integer[] DEFAULT '{0}' NOT NULL,
	"reboot_codes" integer[] DEFAULT '{3010,1641}' NOT NULL,
	"timeout_seconds" integer DEFAULT 3600 NOT NULL,
	"change_note" text DEFAULT '' NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"created_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"approved_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"approved_at" timestamp with time zone
);
--> statement-breakpoint
CREATE UNIQUE INDEX "package_versions_pkg_version_uq" ON "package_versions" USING btree ("package_id","version");
--> statement-breakpoint
-- once approved (or retired), the definition of a package version cannot change
CREATE OR REPLACE FUNCTION package_versions_immutable() RETURNS trigger AS $$
BEGIN
	IF OLD.status <> 'draft' AND (
	   NEW.version IS DISTINCT FROM OLD.version OR NEW.type IS DISTINCT FROM OLD.type
	   OR NEW.file_sha256 IS DISTINCT FROM OLD.file_sha256 OR NEW.package_ref IS DISTINCT FROM OLD.package_ref
	   OR NEW.install_args IS DISTINCT FROM OLD.install_args OR NEW.install_command IS DISTINCT FROM OLD.install_command
	   OR NEW.uninstall_command IS DISTINCT FROM OLD.uninstall_command OR NEW.product_code IS DISTINCT FROM OLD.product_code
	   OR NEW.detection IS DISTINCT FROM OLD.detection OR NEW.success_codes IS DISTINCT FROM OLD.success_codes
	   OR NEW.reboot_codes IS DISTINCT FROM OLD.reboot_codes OR NEW.package_id IS DISTINCT FROM OLD.package_id) THEN
		RAISE EXCEPTION 'approved package versions are immutable' USING ERRCODE = 'insufficient_privilege';
	END IF;
	IF OLD.status = 'retired' AND NEW.status <> 'retired' THEN
		RAISE EXCEPTION 'retired package versions cannot be reactivated' USING ERRCODE = 'insufficient_privilege';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER package_versions_no_change BEFORE UPDATE ON "package_versions"
	FOR EACH ROW EXECUTE FUNCTION package_versions_immutable();
--> statement-breakpoint
CREATE TABLE "deployments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"kind" text NOT NULL,
	"package_version_id" uuid REFERENCES "package_versions"("id") ON DELETE restrict,
	"action" text DEFAULT 'install' NOT NULL,
	"patch_filter" jsonb,
	"rings" jsonb NOT NULL,
	"steps" jsonb NOT NULL,
	"options" jsonb NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"current_ring" integer DEFAULT -1 NOT NULL,
	"ring_started_at" timestamp with time zone,
	"paused_reason" text,
	"approval_id" uuid REFERENCES "approval_requests"("id") ON DELETE set null,
	"created_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone
);
--> statement-breakpoint
CREATE INDEX "deployments_status_idx" ON "deployments" USING btree ("status");
--> statement-breakpoint
ALTER TABLE "job_runs" ADD COLUMN "deployment_id" uuid REFERENCES "deployments"("id") ON DELETE set null;
--> statement-breakpoint
ALTER TABLE "job_runs" ADD COLUMN "ring" integer;
--> statement-breakpoint
CREATE INDEX "job_runs_deployment_idx" ON "job_runs" USING btree ("deployment_id","ring");
--> statement-breakpoint
CREATE TABLE "device_patches" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"device_id" uuid NOT NULL REFERENCES "devices"("id") ON DELETE cascade,
	"source" text NOT NULL,
	"update_id" text NOT NULL,
	"title" text NOT NULL,
	"kb" text,
	"classification" text DEFAULT '' NOT NULL,
	"severity" text DEFAULT '' NOT NULL,
	"security" boolean DEFAULT false NOT NULL,
	"version" text DEFAULT '' NOT NULL,
	"reboot_required" boolean DEFAULT false NOT NULL,
	"detected_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "device_patches_uq" ON "device_patches" USING btree ("device_id","source","update_id");
--> statement-breakpoint
CREATE INDEX "device_patches_update_idx" ON "device_patches" USING btree ("update_id");
--> statement-breakpoint
CREATE TABLE "device_patch_state" (
	"device_id" uuid PRIMARY KEY NOT NULL REFERENCES "devices"("id") ON DELETE cascade,
	"source" text,
	"last_scan_at" timestamp with time zone,
	"last_scan_status" text,
	"last_error" text,
	"reboot_pending" boolean DEFAULT false NOT NULL,
	"scan_requested_at" timestamp with time zone
);
