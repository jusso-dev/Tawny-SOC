CREATE TABLE "soc_agent_room_event" (
	"id" text PRIMARY KEY NOT NULL,
	"sequence" serial NOT NULL,
	"tenant_id" text NOT NULL,
	"run_id" text NOT NULL,
	"event_type" text NOT NULL,
	"status" text NOT NULL,
	"actor_id" text,
	"actor_name" text NOT NULL,
	"agent_id" text,
	"target_agent_id" text,
	"phase_id" text,
	"tool_name" text,
	"summary" text NOT NULL,
	"detail" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "soc_agent_room_event" ADD CONSTRAINT "soc_agent_room_event_run_id_soc_agent_run_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."soc_agent_run"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
CREATE INDEX "soc_agent_room_event_tenant_run_sequence_idx" ON "soc_agent_room_event" USING btree ("tenant_id","run_id","sequence");
--> statement-breakpoint
CREATE INDEX "soc_agent_room_event_run_type_idx" ON "soc_agent_room_event" USING btree ("run_id","event_type");
