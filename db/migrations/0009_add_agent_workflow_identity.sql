ALTER TABLE "soc_agent_run" ADD COLUMN "workflow_id" text;
--> statement-breakpoint
UPDATE "soc_agent_run"
SET "workflow_id" = (
	SELECT workflow_entry.value->>'value'
	FROM jsonb_array_elements("soc_agent_run"."findings") AS workflow_entry(value)
	WHERE workflow_entry.value->>'type' = 'workflow'
	LIMIT 1
);
--> statement-breakpoint
CREATE INDEX "soc_agent_run_tenant_workflow_started_idx" ON "soc_agent_run" USING btree ("tenant_id","workflow_id","started_at");
