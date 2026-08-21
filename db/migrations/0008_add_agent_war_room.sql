CREATE TABLE "soc_agent_run" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"alert_id" text,
	"trigger" text DEFAULT 'manual' NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"title" text NOT NULL,
	"summary" text DEFAULT '' NOT NULL,
	"steps" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"findings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"initiated_by" text NOT NULL,
	"started_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "soc_hunt_schedule" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"name" text NOT NULL,
	"hypothesis" text NOT NULL,
	"query" text NOT NULL,
	"schedule" text NOT NULL,
	"timezone" text DEFAULT 'UTC' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"last_run_at" timestamp with time zone,
	"last_status" text DEFAULT 'never_run' NOT NULL,
	"last_finding_count" integer DEFAULT 0 NOT NULL,
	"created_by" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "soc_agent_run" ADD CONSTRAINT "soc_agent_run_alert_id_soc_alert_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."soc_alert"("id") ON DELETE set null ON UPDATE no action;
--> statement-breakpoint
CREATE INDEX "soc_agent_run_tenant_started_idx" ON "soc_agent_run" USING btree ("tenant_id","started_at");
--> statement-breakpoint
CREATE INDEX "soc_agent_run_alert_idx" ON "soc_agent_run" USING btree ("alert_id");
--> statement-breakpoint
CREATE INDEX "soc_hunt_schedule_tenant_enabled_idx" ON "soc_hunt_schedule" USING btree ("tenant_id","enabled");
