ALTER TABLE "devices" ADD COLUMN "agent_started_at" timestamp with time zone;
--> statement-breakpoint
CREATE TABLE "custom_fields" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"label" text NOT NULL,
	"type" text DEFAULT 'string' NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "custom_fields_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "device_custom_values" (
	"device_id" uuid NOT NULL REFERENCES "devices"("id") ON DELETE cascade,
	"field_id" uuid NOT NULL REFERENCES "custom_fields"("id") ON DELETE cascade,
	"value" text NOT NULL,
	"source" text DEFAULT 'manual' NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "device_custom_values_device_id_field_id_pk" PRIMARY KEY("device_id","field_id")
);
--> statement-breakpoint
CREATE TABLE "scripts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"interpreter" text NOT NULL,
	"created_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "scripts_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "script_versions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"script_id" uuid NOT NULL REFERENCES "scripts"("id") ON DELETE cascade,
	"version" integer NOT NULL,
	"content" text NOT NULL,
	"sha256" text NOT NULL,
	"parameters" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"change_note" text DEFAULT '' NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"created_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"approved_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"approved_at" timestamp with time zone
);
--> statement-breakpoint
CREATE UNIQUE INDEX "script_versions_script_version_uq" ON "script_versions" USING btree ("script_id","version");
--> statement-breakpoint
-- script content is immutable: only status/approval columns may change
CREATE OR REPLACE FUNCTION script_versions_immutable() RETURNS trigger AS $$
BEGIN
	IF NEW.content IS DISTINCT FROM OLD.content OR NEW.sha256 IS DISTINCT FROM OLD.sha256
	   OR NEW.parameters IS DISTINCT FROM OLD.parameters OR NEW.version IS DISTINCT FROM OLD.version
	   OR NEW.script_id IS DISTINCT FROM OLD.script_id THEN
		RAISE EXCEPTION 'script versions are immutable' USING ERRCODE = 'insufficient_privilege';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER script_versions_no_content_change BEFORE UPDATE ON "script_versions"
	FOR EACH ROW EXECUTE FUNCTION script_versions_immutable();
--> statement-breakpoint
CREATE TABLE "jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"trigger" text NOT NULL,
	"run_at" timestamp with time zone,
	"cron" text,
	"timezone" text DEFAULT 'UTC' NOT NULL,
	"next_run_at" timestamp with time zone,
	"last_run_at" timestamp with time zone,
	"targets" jsonb NOT NULL,
	"options" jsonb NOT NULL,
	"created_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "jobs_next_run_idx" ON "jobs" USING btree ("next_run_at") WHERE "enabled" AND "next_run_at" IS NOT NULL;
--> statement-breakpoint
CREATE TABLE "job_steps" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"job_id" uuid NOT NULL REFERENCES "jobs"("id") ON DELETE cascade,
	"position" integer NOT NULL,
	"script_version_id" uuid NOT NULL REFERENCES "script_versions"("id") ON DELETE restrict,
	"params" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"continue_on_error" boolean DEFAULT false NOT NULL,
	"custom_field_id" uuid REFERENCES "custom_fields"("id") ON DELETE set null
);
--> statement-breakpoint
CREATE UNIQUE INDEX "job_steps_job_position_uq" ON "job_steps" USING btree ("job_id","position");
--> statement-breakpoint
CREATE TABLE "job_runs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"job_id" uuid REFERENCES "jobs"("id") ON DELETE cascade,
	"name" text NOT NULL,
	"trigger" text NOT NULL,
	"triggered_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"steps" jsonb NOT NULL,
	"options" jsonb NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone
);
--> statement-breakpoint
CREATE INDEX "job_runs_job_idx" ON "job_runs" USING btree ("job_id","created_at");
--> statement-breakpoint
CREATE TABLE "tasks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"run_id" uuid NOT NULL REFERENCES "job_runs"("id") ON DELETE cascade,
	"device_id" uuid NOT NULL REFERENCES "devices"("id") ON DELETE cascade,
	"status" text DEFAULT 'pending' NOT NULL,
	"attempt" integer DEFAULT 1 NOT NULL,
	"not_before" timestamp with time zone DEFAULT now() NOT NULL,
	"dispatched_at" timestamp with time zone,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"exit_code" integer,
	"error" text,
	"cancel_requested" boolean DEFAULT false NOT NULL,
	"step_results" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"output_bytes" integer DEFAULT 0 NOT NULL,
	"output_truncated" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "tasks_device_status_idx" ON "tasks" USING btree ("device_id","status");
--> statement-breakpoint
CREATE INDEX "tasks_run_idx" ON "tasks" USING btree ("run_id");
--> statement-breakpoint
CREATE TABLE "task_output" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"task_id" uuid NOT NULL REFERENCES "tasks"("id") ON DELETE cascade,
	"stream" text NOT NULL,
	"data" text NOT NULL,
	"at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "task_output_task_idx" ON "task_output" USING btree ("task_id","id");
