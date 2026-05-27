CREATE TABLE "soc_comment" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"incident_id" text,
	"alert_id" text,
	"author" text NOT NULL,
	"body" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "soc_delivery_log" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"channel" text NOT NULL,
	"target" text NOT NULL,
	"state" text NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"last_attempt_at" timestamp with time zone NOT NULL,
	"error" text,
	"external_ref" text
);
--> statement-breakpoint
CREATE TABLE "soc_incident" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"number" text NOT NULL,
	"title" text NOT NULL,
	"severity" text NOT NULL,
	"priority" text NOT NULL,
	"status" text NOT NULL,
	"assignee" text,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"tlp" text DEFAULT 'amber' NOT NULL,
	"pap" text DEFAULT 'green' NOT NULL,
	"classification" text DEFAULT 'undetermined' NOT NULL,
	"mitre_techniques" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"observables" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"linked_hosts" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"kelpie_case_id" text,
	"kelpie_url" text,
	"kelpie_sync_status" text DEFAULT 'not_synced' NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL,
	"closed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "soc_incident_alert" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"incident_id" text NOT NULL,
	"alert_id" text NOT NULL,
	"added_by" text,
	"added_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "soc_kelpie_integration" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"base_url" text NOT NULL,
	"token_reference" text,
	"enabled" boolean DEFAULT false NOT NULL,
	"dedupe_by" text DEFAULT 'externalRef' NOT NULL,
	"sync_fields" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "soc_playbook" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text NOT NULL,
	"severity" text NOT NULL,
	"owner" text NOT NULL,
	"steps" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "soc_task" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"incident_id" text NOT NULL,
	"title" text NOT NULL,
	"owner" text NOT NULL,
	"status" text NOT NULL,
	"due_at" timestamp with time zone,
	"required_evidence" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"response_action" text
);
--> statement-breakpoint
CREATE TABLE "soc_threat_intel_feed" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"name" text NOT NULL,
	"type" text NOT NULL,
	"url" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"status" text DEFAULT 'healthy' NOT NULL,
	"indicator_count" integer DEFAULT 0 NOT NULL,
	"last_run_at" timestamp with time zone,
	"last_error" text
);
--> statement-breakpoint
CREATE TABLE "soc_timeline" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"incident_id" text,
	"alert_id" text,
	"actor" text NOT NULL,
	"action" text NOT NULL,
	"detail" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "soc_comment" ADD CONSTRAINT "soc_comment_incident_id_soc_incident_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."soc_incident"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "soc_comment" ADD CONSTRAINT "soc_comment_alert_id_soc_alert_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."soc_alert"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "soc_incident_alert" ADD CONSTRAINT "soc_incident_alert_incident_id_soc_incident_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."soc_incident"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "soc_incident_alert" ADD CONSTRAINT "soc_incident_alert_alert_id_soc_alert_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."soc_alert"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "soc_task" ADD CONSTRAINT "soc_task_incident_id_soc_incident_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."soc_incident"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "soc_timeline" ADD CONSTRAINT "soc_timeline_incident_id_soc_incident_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."soc_incident"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "soc_timeline" ADD CONSTRAINT "soc_timeline_alert_id_soc_alert_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."soc_alert"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "soc_comment_tenant_created_idx" ON "soc_comment" USING btree ("tenant_id","created_at");--> statement-breakpoint
CREATE INDEX "soc_delivery_tenant_state_idx" ON "soc_delivery_log" USING btree ("tenant_id","state");--> statement-breakpoint
CREATE INDEX "soc_incident_tenant_status_idx" ON "soc_incident" USING btree ("tenant_id","status");--> statement-breakpoint
CREATE INDEX "soc_incident_number_idx" ON "soc_incident" USING btree ("tenant_id","number");--> statement-breakpoint
CREATE INDEX "soc_incident_alert_tenant_idx" ON "soc_incident_alert" USING btree ("tenant_id","incident_id");--> statement-breakpoint
CREATE INDEX "soc_kelpie_tenant_idx" ON "soc_kelpie_integration" USING btree ("tenant_id");--> statement-breakpoint
CREATE INDEX "soc_playbook_tenant_enabled_idx" ON "soc_playbook" USING btree ("tenant_id","enabled");--> statement-breakpoint
CREATE INDEX "soc_task_tenant_status_idx" ON "soc_task" USING btree ("tenant_id","status");--> statement-breakpoint
CREATE INDEX "soc_ti_feed_tenant_status_idx" ON "soc_threat_intel_feed" USING btree ("tenant_id","status");--> statement-breakpoint
CREATE INDEX "soc_timeline_tenant_created_idx" ON "soc_timeline" USING btree ("tenant_id","created_at");