CREATE TABLE "webhooks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"url" text NOT NULL,
	"events" text[] DEFAULT '{}' NOT NULL,
	"secret_enc" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "webhook_deliveries" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"webhook_id" uuid NOT NULL REFERENCES "webhooks"("id") ON DELETE cascade,
	"event" text NOT NULL,
	"payload" jsonb NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"next_attempt_at" timestamp with time zone DEFAULT now() NOT NULL,
	"response_status" integer,
	"last_error" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"delivered_at" timestamp with time zone
);
--> statement-breakpoint
CREATE INDEX "webhook_deliveries_due_idx" ON "webhook_deliveries" USING btree ("status","next_attempt_at");
--> statement-breakpoint
CREATE INDEX "webhook_deliveries_hook_idx" ON "webhook_deliveries" USING btree ("webhook_id","created_at");
--> statement-breakpoint
CREATE TABLE "reports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"source" text NOT NULL,
	"columns" text[] NOT NULL,
	"filters" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"sort" jsonb,
	"shared" boolean DEFAULT false NOT NULL,
	"created_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "metrics_daily" (
	"day" date NOT NULL,
	"key" text NOT NULL,
	"value" double precision NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	PRIMARY KEY ("day", "key")
);
--> statement-breakpoint
CREATE TABLE "licenses" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"vendor" text DEFAULT '' NOT NULL,
	"software_pattern" text NOT NULL,
	"publisher_pattern" text,
	"software_regex" text NOT NULL,
	"publisher_regex" text,
	"seats" integer NOT NULL,
	"expires_at" date,
	"cost" numeric(12, 2),
	"notes" text DEFAULT '' NOT NULL,
	"overused" boolean DEFAULT false NOT NULL,
	"created_by" uuid REFERENCES "users"("id") ON DELETE set null,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
