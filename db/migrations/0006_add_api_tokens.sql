CREATE TABLE "soc_api_token" (
	"id" text PRIMARY KEY NOT NULL,
	"tenant_id" text NOT NULL,
	"name" text NOT NULL,
	"token_hash" text NOT NULL,
	"token_prefix" text NOT NULL,
	"role" text DEFAULT 'member' NOT NULL,
	"scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"last_used_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"created_by" text,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	CONSTRAINT "soc_api_token_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE INDEX "soc_api_token_tenant_status_idx" ON "soc_api_token" USING btree ("tenant_id","status");
--> statement-breakpoint
CREATE INDEX "soc_api_token_hash_idx" ON "soc_api_token" USING btree ("token_hash");
