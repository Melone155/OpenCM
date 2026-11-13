ALTER TABLE "device_software" ADD COLUMN "source_name" text;
--> statement-breakpoint
ALTER TABLE "device_software" ADD COLUMN "source_version" text;
--> statement-breakpoint
CREATE TABLE "osv_packages" (
	"ecosystem" text NOT NULL,
	"name" text NOT NULL,
	"version" text NOT NULL,
	"vuln_ids" text[] DEFAULT '{}' NOT NULL,
	"checked_at" timestamp with time zone DEFAULT now() NOT NULL,
	PRIMARY KEY ("ecosystem", "name", "version")
);
--> statement-breakpoint
CREATE INDEX "osv_packages_checked_idx" ON "osv_packages" USING btree ("checked_at");
--> statement-breakpoint
CREATE TABLE "osv_vulns" (
	"id" text PRIMARY KEY NOT NULL,
	"summary" text DEFAULT '' NOT NULL,
	"cve_ids" text[] DEFAULT '{}' NOT NULL,
	"modified" timestamp with time zone,
	"fetched_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "device_security" (
	"device_id" uuid PRIMARY KEY NOT NULL REFERENCES "devices"("id") ON DELETE cascade,
	"collected_at" timestamp with time zone NOT NULL,
	"encryption" text DEFAULT 'unknown' NOT NULL,
	"antivirus" text DEFAULT 'unknown' NOT NULL,
	"firewall" text DEFAULT 'unknown' NOT NULL,
	"secure_boot" boolean,
	"tpm" text DEFAULT 'unknown' NOT NULL,
	"compliant" boolean DEFAULT false NOT NULL,
	"issues" text[] DEFAULT '{}' NOT NULL,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "device_security_state_idx" ON "device_security" USING btree ("compliant","encryption","antivirus");
--> statement-breakpoint
CREATE TABLE "assets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"type" text DEFAULT 'other' NOT NULL,
	"status" text DEFAULT 'in_use' NOT NULL,
	"manufacturer" text DEFAULT '' NOT NULL,
	"model" text DEFAULT '' NOT NULL,
	"serial_number" text,
	"inventory_number" text,
	"location" text DEFAULT '' NOT NULL,
	"assigned_to" text DEFAULT '' NOT NULL,
	"ip_address" text,
	"mac_address" text,
	"purchase_date" date,
	"warranty_until" date,
	"cost" numeric(12, 2),
	"device_id" uuid REFERENCES "devices"("id") ON DELETE set null,
	"notes" text DEFAULT '' NOT NULL,
	"created_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "assets_inventory_number_uq" ON "assets" USING btree (lower("inventory_number")) WHERE "inventory_number" IS NOT NULL;
--> statement-breakpoint
CREATE INDEX "assets_serial_idx" ON "assets" USING btree (lower("serial_number"));
--> statement-breakpoint
CREATE INDEX "assets_device_idx" ON "assets" USING btree ("device_id");
--> statement-breakpoint
CREATE INDEX "assets_type_idx" ON "assets" USING btree ("type","status");
