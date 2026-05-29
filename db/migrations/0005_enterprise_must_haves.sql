CREATE TABLE "soc_ingest_source" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"name" text NOT NULL,
	"source_type" text NOT NULL,
	"auth_mode" text DEFAULT 'shared-secret' NOT NULL,
	"parser" text DEFAULT 'generic-json' NOT NULL,
	"status" text DEFAULT 'untested' NOT NULL,
	"last_seen_at" timestamp with time zone,
	"last_error" text,
	"throughput" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "soc_ingest_dead_letter" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"source_id" text,
	"reason" text NOT NULL,
	"payload" jsonb NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"received_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "soc_connector" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"catalog_id" text NOT NULL,
	"provider" text NOT NULL,
	"category" text NOT NULL,
	"name" text NOT NULL,
	"auth_type" text NOT NULL,
	"status" text DEFAULT 'untested' NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"schedule" text DEFAULT 'manual' NOT NULL,
	"config" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"credential_reference" text,
	"last_test_at" timestamp with time zone,
	"last_sync_at" timestamp with time zone,
	"last_error" text,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "soc_report" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"framework" text NOT NULL,
	"title" text NOT NULL,
	"status" text DEFAULT 'draft' NOT NULL,
	"schedule" text DEFAULT 'manual' NOT NULL,
	"evidence" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"generated_at" timestamp with time zone,
	"created_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "soc_retention_policy" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"target" text NOT NULL,
	"hot_days" integer DEFAULT 30 NOT NULL,
	"archive_days" integer DEFAULT 180 NOT NULL,
	"delete_after_days" integer DEFAULT 365 NOT NULL,
	"preserve_case_evidence" boolean DEFAULT true NOT NULL,
	"legal_hold" boolean DEFAULT false NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "soc_evidence" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"incident_id" text,
	"alert_id" text,
	"evidence_type" text NOT NULL,
	"title" text NOT NULL,
	"source_ref" text,
	"checksum" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_by" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "soc_audit_log" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"actor_id" text,
	"actor_name" text,
	"action" text NOT NULL,
	"resource_type" text NOT NULL,
	"resource_id" text,
	"detail" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "soc_ingest_dead_letter" ADD CONSTRAINT "soc_ingest_dead_letter_source_id_soc_ingest_source_id_fk" FOREIGN KEY ("source_id") REFERENCES "public"."soc_ingest_source"("id") ON DELETE set null ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "soc_evidence" ADD CONSTRAINT "soc_evidence_incident_id_soc_incident_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."soc_incident"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "soc_evidence" ADD CONSTRAINT "soc_evidence_alert_id_soc_alert_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."soc_alert"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
CREATE INDEX "soc_ingest_source_tenant_status_idx" ON "soc_ingest_source" USING btree ("tenant_id","status");
--> statement-breakpoint
CREATE INDEX "soc_ingest_dead_letter_tenant_status_idx" ON "soc_ingest_dead_letter" USING btree ("tenant_id","status");
--> statement-breakpoint
CREATE INDEX "soc_connector_tenant_status_idx" ON "soc_connector" USING btree ("tenant_id","status");
--> statement-breakpoint
CREATE INDEX "soc_connector_catalog_idx" ON "soc_connector" USING btree ("catalog_id");
--> statement-breakpoint
CREATE INDEX "soc_report_tenant_framework_idx" ON "soc_report" USING btree ("tenant_id","framework");
--> statement-breakpoint
CREATE UNIQUE INDEX "soc_retention_policy_tenant_target_idx" ON "soc_retention_policy" USING btree ("tenant_id","target");
--> statement-breakpoint
CREATE INDEX "soc_evidence_tenant_incident_idx" ON "soc_evidence" USING btree ("tenant_id","incident_id");
--> statement-breakpoint
CREATE INDEX "soc_audit_log_tenant_created_idx" ON "soc_audit_log" USING btree ("tenant_id","created_at");
