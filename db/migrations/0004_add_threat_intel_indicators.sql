CREATE TABLE "soc_threat_intel_indicator" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"feed_id" text NOT NULL,
	"type" text NOT NULL,
	"value" text NOT NULL,
	"source_feed" text NOT NULL,
	"confidence" integer DEFAULT 80 NOT NULL,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"first_seen" timestamp with time zone NOT NULL,
	"last_seen" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone,
	CONSTRAINT "soc_threat_intel_indicator_feed_id_soc_threat_intel_feed_id_fk" FOREIGN KEY ("feed_id") REFERENCES "public"."soc_threat_intel_feed"("id") ON DELETE cascade ON UPDATE no action
);
--> statement-breakpoint
CREATE INDEX "soc_ti_indicator_tenant_type_idx" ON "soc_threat_intel_indicator" USING btree ("tenant_id","type");
--> statement-breakpoint
CREATE INDEX "soc_ti_indicator_feed_idx" ON "soc_threat_intel_indicator" USING btree ("feed_id");
--> statement-breakpoint
CREATE UNIQUE INDEX "soc_ti_indicator_tenant_feed_value_idx" ON "soc_threat_intel_indicator" USING btree ("tenant_id","feed_id","value");
