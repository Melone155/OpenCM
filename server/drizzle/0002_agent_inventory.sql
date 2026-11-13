ALTER TABLE "devices" ADD COLUMN "arch" text DEFAULT '' NOT NULL;
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "machine_id" text;
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "status" text DEFAULT 'active' NOT NULL;
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "cert_fingerprint" text;
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "cert_serial" text;
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "cert_expires_at" timestamp with time zone;
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "manufacturer" text;
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "model" text;
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "serial_number" text;
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "logged_on_user" text;
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "last_ip" "inet";
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "inventory_requested" boolean DEFAULT true NOT NULL;
--> statement-breakpoint
ALTER TABLE "devices" ADD COLUMN "last_inventory_at" timestamp with time zone;
--> statement-breakpoint
CREATE UNIQUE INDEX "devices_machine_id_uq" ON "devices" USING btree ("machine_id");
--> statement-breakpoint
CREATE UNIQUE INDEX "devices_cert_fp_uq" ON "devices" USING btree ("cert_fingerprint");
--> statement-breakpoint
CREATE TABLE "enrollment_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"token_hash" text NOT NULL,
	"created_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"device_group_id" uuid REFERENCES "device_groups"("id") ON DELETE set null,
	"max_uses" integer,
	"uses" integer DEFAULT 0 NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "enrollment_tokens_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "device_inventory" (
	"device_id" uuid PRIMARY KEY NOT NULL REFERENCES "devices"("id") ON DELETE cascade,
	"collected_at" timestamp with time zone NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	"data" jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "device_software" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"device_id" uuid NOT NULL REFERENCES "devices"("id") ON DELETE cascade,
	"name" text NOT NULL,
	"version" text DEFAULT '' NOT NULL,
	"publisher" text DEFAULT '' NOT NULL,
	"install_date" text,
	"source" text DEFAULT '' NOT NULL,
	"arch" text DEFAULT '' NOT NULL
);
--> statement-breakpoint
CREATE INDEX "device_software_device_idx" ON "device_software" USING btree ("device_id");
--> statement-breakpoint
CREATE INDEX "device_software_name_idx" ON "device_software" USING btree ("name");
--> statement-breakpoint
CREATE TABLE "device_history" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"device_id" uuid NOT NULL REFERENCES "devices"("id") ON DELETE cascade,
	"at" timestamp with time zone DEFAULT now() NOT NULL,
	"category" text NOT NULL,
	"change" text NOT NULL,
	"item_key" text NOT NULL,
	"old_value" jsonb,
	"new_value" jsonb
);
--> statement-breakpoint
CREATE INDEX "device_history_device_at_idx" ON "device_history" USING btree ("device_id","at");
