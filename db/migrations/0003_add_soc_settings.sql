CREATE TABLE IF NOT EXISTS "soc_setting" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"key" text NOT NULL,
	"value" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
CREATE INDEX IF NOT EXISTS "soc_setting_tenant_key_idx" ON "soc_setting" USING btree ("tenant_id","key");
ALTER TABLE "soc_threat_intel_feed" ALTER COLUMN "status" SET DEFAULT 'paused';
