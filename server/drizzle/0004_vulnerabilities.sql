CREATE TABLE "vulnerabilities" (
	"cve_id" text PRIMARY KEY NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"published" timestamp with time zone,
	"last_modified" timestamp with time zone,
	"vuln_status" text DEFAULT '' NOT NULL,
	"cvss_score" real,
	"cvss_severity" text,
	"cvss_version" text,
	"cvss_vector" text,
	"cwes" text[] DEFAULT '{}' NOT NULL,
	"refs" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"kev" boolean DEFAULT false NOT NULL,
	"kev_date_added" text,
	"kev_due_date" text,
	"kev_ransomware" text,
	"kev_required_action" text,
	"epss" real,
	"epss_percentile" real,
	"epss_date" text,
	"accepted_at" timestamp with time zone,
	"accepted_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"accepted_reason" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "vulnerabilities_kev_idx" ON "vulnerabilities" USING btree ("kev");
--> statement-breakpoint
CREATE INDEX "vulnerabilities_severity_idx" ON "vulnerabilities" USING btree ("cvss_severity");
--> statement-breakpoint
CREATE TABLE "vuln_cpe_matches" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"cve_id" text NOT NULL REFERENCES "vulnerabilities"("cve_id") ON DELETE cascade,
	"vendor" text NOT NULL,
	"product" text NOT NULL,
	"version" text DEFAULT '*' NOT NULL,
	"target_sw" text DEFAULT '*' NOT NULL,
	"version_start_including" text,
	"version_start_excluding" text,
	"version_end_including" text,
	"version_end_excluding" text
);
--> statement-breakpoint
CREATE INDEX "vuln_cpe_matches_product_idx" ON "vuln_cpe_matches" USING btree ("product","vendor");
--> statement-breakpoint
CREATE INDEX "vuln_cpe_matches_cve_idx" ON "vuln_cpe_matches" USING btree ("cve_id");
--> statement-breakpoint
CREATE TABLE "cpe_rules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name_pattern" text NOT NULL,
	"publisher_pattern" text,
	"source" text,
	"vendor" text,
	"product" text,
	"ignore" boolean DEFAULT false NOT NULL,
	"priority" integer DEFAULT 100 NOT NULL,
	"origin" text DEFAULT 'user' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"note" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "device_vulnerabilities" (
	"device_id" uuid NOT NULL REFERENCES "devices"("id") ON DELETE cascade,
	"cve_id" text NOT NULL REFERENCES "vulnerabilities"("cve_id") ON DELETE cascade,
	"software_name" text NOT NULL,
	"software_version" text NOT NULL,
	"vendor" text NOT NULL,
	"product" text NOT NULL,
	"confidence" text NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"first_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen" timestamp with time zone DEFAULT now() NOT NULL,
	"fixed_at" timestamp with time zone,
	CONSTRAINT "device_vulnerabilities_device_id_cve_id_software_name_pk" PRIMARY KEY("device_id","cve_id","software_name")
);
--> statement-breakpoint
CREATE INDEX "device_vulns_cve_idx" ON "device_vulnerabilities" USING btree ("cve_id","status");
--> statement-breakpoint
CREATE INDEX "device_vulns_status_idx" ON "device_vulnerabilities" USING btree ("status");
--> statement-breakpoint
CREATE TABLE "feed_state" (
	"name" text PRIMARY KEY NOT NULL,
	"last_success_at" timestamp with time zone,
	"last_attempt_at" timestamp with time zone,
	"cursor" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"error" text,
	"locked_until" timestamp with time zone,
	"requested_at" timestamp with time zone,
	"stats" jsonb DEFAULT '{}'::jsonb NOT NULL
);
