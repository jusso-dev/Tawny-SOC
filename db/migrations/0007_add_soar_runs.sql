CREATE TABLE "soc_playbook_run" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"playbook_id" text NOT NULL,
	"playbook_name" text NOT NULL,
	"incident_id" text NOT NULL,
	"status" text NOT NULL,
	"trigger" text DEFAULT 'manual' NOT NULL,
	"dry_run" boolean DEFAULT true NOT NULL,
	"actor_id" text,
	"actor_name" text NOT NULL,
	"summary" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"started_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "soc_playbook_action" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"run_id" text NOT NULL,
	"incident_id" text NOT NULL,
	"phase" text NOT NULL,
	"position" integer NOT NULL,
	"action" text NOT NULL,
	"kind" text NOT NULL,
	"status" text NOT NULL,
	"approval_required" boolean DEFAULT false NOT NULL,
	"input" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"output" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"approved_by" text,
	"approved_at" timestamp with time zone,
	"created_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "soc_playbook_run" ADD CONSTRAINT "soc_playbook_run_incident_id_soc_incident_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."soc_incident"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "soc_playbook_action" ADD CONSTRAINT "soc_playbook_action_run_id_soc_playbook_run_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."soc_playbook_run"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "soc_playbook_action" ADD CONSTRAINT "soc_playbook_action_incident_id_soc_incident_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."soc_incident"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
CREATE INDEX "soc_playbook_run_tenant_started_idx" ON "soc_playbook_run" USING btree ("tenant_id","started_at");
--> statement-breakpoint
CREATE INDEX "soc_playbook_run_incident_idx" ON "soc_playbook_run" USING btree ("incident_id");
--> statement-breakpoint
CREATE INDEX "soc_playbook_action_run_position_idx" ON "soc_playbook_action" USING btree ("run_id","position");
--> statement-breakpoint
CREATE INDEX "soc_playbook_action_tenant_status_idx" ON "soc_playbook_action" USING btree ("tenant_id","status");
