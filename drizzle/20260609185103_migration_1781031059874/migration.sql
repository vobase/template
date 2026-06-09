-- One-off DML / DDL staging area
-- Inline SQL here gets prepended to the next `db:generate` migration and
-- baked into history; this file resets to empty afterwards. Use --!include
-- to pull in shared SQL fragments via glob.
--
-- Extensions + nanoid + functions + triggers are NOT included here — they
-- already live in the initial migration (baked once at first db:generate)
-- and don't need to re-run on subsequent migrations.

CREATE SCHEMA "audit";
--> statement-breakpoint
CREATE SCHEMA "harness";
--> statement-breakpoint
CREATE SCHEMA "infra";
--> statement-breakpoint
CREATE SCHEMA "auth";
--> statement-breakpoint
CREATE SCHEMA "agents";
--> statement-breakpoint
CREATE SCHEMA "automations";
--> statement-breakpoint
CREATE SCHEMA "changes";
--> statement-breakpoint
CREATE SCHEMA "channels";
--> statement-breakpoint
CREATE SCHEMA "contacts";
--> statement-breakpoint
CREATE SCHEMA "drive";
--> statement-breakpoint
CREATE SCHEMA "integrations";
--> statement-breakpoint
CREATE SCHEMA "messaging";
--> statement-breakpoint
CREATE SCHEMA "settings";
--> statement-breakpoint
CREATE SCHEMA "team";
--> statement-breakpoint
CREATE SCHEMA "views";
--> statement-breakpoint
CREATE TABLE "audit"."audit_log" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"event" text NOT NULL,
	"actor_id" text,
	"actor_email" text,
	"ip" text,
	"details" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit"."record_audits" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"table_name" text NOT NULL,
	"record_id" text NOT NULL,
	"old_data" text,
	"new_data" text,
	"changed_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "infra"."channels_log" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"channel" text NOT NULL,
	"direction" text NOT NULL,
	"to" text NOT NULL,
	"from" text,
	"message_id" text,
	"status" text DEFAULT 'sent' NOT NULL,
	"content" text,
	"error" text,
	"metadata" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "channels_log_direction_check" CHECK (direction IN ('inbound', 'outbound'))
);
--> statement-breakpoint
CREATE TABLE "infra"."channels_templates" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"channel" text NOT NULL,
	"external_id" text UNIQUE,
	"name" text NOT NULL,
	"language" text NOT NULL,
	"category" text,
	"status" text,
	"components" text,
	"synced_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "harness"."active_wakes" (
	"conversation_id" text PRIMARY KEY,
	"worker_id" text NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"debounce_until" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "harness"."messages" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"thread_id" text NOT NULL,
	"seq" integer NOT NULL,
	"payload" jsonb NOT NULL,
	"payload_version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "harness"."audit_wake_map" (
	"audit_log_id" text PRIMARY KEY,
	"wake_id" text NOT NULL,
	"conversation_id" text NOT NULL,
	"event_type" text NOT NULL,
	"organization_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "harness"."conversation_events" (
	"id" bigserial PRIMARY KEY,
	"conversation_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"wake_id" text,
	"turn_index" integer NOT NULL,
	"ts" timestamp with time zone DEFAULT now() NOT NULL,
	"type" text NOT NULL,
	"role" text,
	"content" text,
	"tool_call_id" text,
	"tool_calls" jsonb,
	"tool_name" text,
	"reasoning" text,
	"reasoning_details" jsonb,
	"token_count" integer,
	"finish_reason" text,
	"llm_task" text,
	"tokens_in" integer,
	"tokens_out" integer,
	"cache_read_tokens" integer,
	"cost_usd" numeric(10,6),
	"latency_ms" integer,
	"model" text,
	"provider" text,
	"payload" jsonb
);
--> statement-breakpoint
CREATE TABLE "harness"."pending_approvals" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"wake_id" text NOT NULL,
	"conversation_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"turn_index" integer NOT NULL,
	"tool_call_id" text NOT NULL,
	"tool_name" text NOT NULL,
	"tool_input" jsonb NOT NULL,
	"reason" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"decided_by_user_id" text,
	"decided_note" text,
	"requested_at" timestamp with time zone DEFAULT now() NOT NULL,
	"decided_at" timestamp with time zone,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "harness"."tenant_cost_daily" (
	"organization_id" text,
	"date" date,
	"llm_task" text,
	"tokens_in" bigint,
	"tokens_out" bigint,
	"cache_read_tokens" bigint,
	"cost_usd" numeric(12,4),
	"call_count" integer,
	CONSTRAINT "tenant_cost_daily_pkey" PRIMARY KEY("organization_id","date","llm_task")
);
--> statement-breakpoint
CREATE TABLE "harness"."threads" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"agent_id" text NOT NULL,
	"kind" text NOT NULL,
	"conversation_id" text,
	"cron_key" text,
	"parent_thread_id" text,
	"compacted_at" timestamp with time zone,
	"message_count" integer DEFAULT 0 NOT NULL,
	"last_active_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "infra"."integrations" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"provider" text NOT NULL,
	"auth_type" text NOT NULL,
	"label" text,
	"status" text DEFAULT 'active' NOT NULL,
	"config" text NOT NULL,
	"scopes" text,
	"config_expires_at" timestamp with time zone,
	"last_refresh_at" timestamp with time zone,
	"auth_failed_at" timestamp with time zone,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "integrations_status_check" CHECK (status IN ('active', 'inactive', 'disconnected', 'error'))
);
--> statement-breakpoint
CREATE TABLE "infra"."rate_limits" (
	"key" text,
	"hit_at" timestamp with time zone,
	"seq" integer,
	CONSTRAINT "rate_limits_pkey" PRIMARY KEY("key","hit_at","seq")
);
--> statement-breakpoint
CREATE TABLE "infra"."sequences" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"prefix" text NOT NULL UNIQUE,
	"current_value" integer DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "infra"."storage_objects" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"bucket" text NOT NULL,
	"key" text NOT NULL,
	"size" integer NOT NULL,
	"content_type" text DEFAULT 'application/octet-stream' NOT NULL,
	"metadata" text,
	"uploaded_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "infra"."webhook_dedup" (
	"id" text,
	"source" text,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "webhook_dedup_pkey" PRIMARY KEY("id","source")
);
--> statement-breakpoint
CREATE TABLE "auth"."account" (
	"id" text PRIMARY KEY,
	"account_id" text NOT NULL,
	"provider_id" text NOT NULL,
	"user_id" text NOT NULL,
	"access_token" text,
	"refresh_token" text,
	"id_token" text,
	"access_token_expires_at" timestamp with time zone,
	"refresh_token_expires_at" timestamp with time zone,
	"scope" text,
	"password" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth"."apikey" (
	"id" text PRIMARY KEY,
	"config_id" text DEFAULT 'default' NOT NULL,
	"name" text,
	"start" text,
	"reference_id" text NOT NULL,
	"prefix" text,
	"key" text NOT NULL,
	"refill_interval" integer,
	"refill_amount" integer,
	"last_refill_at" timestamp with time zone,
	"enabled" boolean DEFAULT true,
	"rate_limit_enabled" boolean DEFAULT true,
	"rate_limit_time_window" integer DEFAULT 60000,
	"rate_limit_max" integer DEFAULT 600,
	"request_count" integer DEFAULT 0,
	"remaining" integer,
	"last_request" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"permissions" text,
	"metadata" text
);
--> statement-breakpoint
CREATE TABLE "auth"."invitation" (
	"id" text PRIMARY KEY,
	"organization_id" text NOT NULL,
	"email" text NOT NULL,
	"role" text,
	"team_id" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"inviter_id" text NOT NULL,
	"phone_number" text
);
--> statement-breakpoint
CREATE TABLE "auth"."member" (
	"id" text PRIMARY KEY,
	"organization_id" text NOT NULL,
	"user_id" text NOT NULL,
	"role" text DEFAULT 'member' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth"."organization" (
	"id" text PRIMARY KEY,
	"name" text NOT NULL,
	"slug" text NOT NULL UNIQUE,
	"logo" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"metadata" text
);
--> statement-breakpoint
CREATE TABLE "auth"."session" (
	"id" text PRIMARY KEY,
	"expires_at" timestamp with time zone NOT NULL,
	"token" text NOT NULL UNIQUE,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ip_address" text,
	"user_agent" text,
	"user_id" text NOT NULL,
	"active_organization_id" text,
	"active_team_id" text
);
--> statement-breakpoint
CREATE TABLE "auth"."team" (
	"id" text PRIMARY KEY,
	"name" text NOT NULL,
	"organization_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "auth"."team_member" (
	"id" text PRIMARY KEY,
	"team_id" text NOT NULL,
	"user_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "auth"."user" (
	"id" text PRIMARY KEY,
	"name" text NOT NULL,
	"email" text NOT NULL UNIQUE,
	"email_verified" boolean DEFAULT false NOT NULL,
	"image" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"is_anonymous" boolean DEFAULT false,
	"phone_number" text UNIQUE,
	"phone_number_verified" boolean
);
--> statement-breakpoint
CREATE TABLE "auth"."verification" (
	"id" text PRIMARY KEY,
	"identifier" text NOT NULL,
	"value" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agents"."agent_definitions" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"instructions" text DEFAULT '' NOT NULL,
	"model" text DEFAULT 'anthropic/claude-sonnet-4-6' NOT NULL,
	"max_steps" integer DEFAULT 20,
	"working_memory" text DEFAULT '' NOT NULL,
	"skill_allowlist" text[],
	"card_approval_required" boolean DEFAULT true NOT NULL,
	"file_approval_required" boolean DEFAULT true NOT NULL,
	"book_slot_approval_required" boolean DEFAULT true NOT NULL,
	"max_output_tokens" integer DEFAULT 4096,
	"max_input_tokens" integer DEFAULT 32768,
	"max_turns_per_wake" integer DEFAULT 10,
	"soft_cost_ceiling_usd" numeric(10,4),
	"hard_cost_ceiling_usd" numeric(10,4),
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agents"."agent_scores" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"conversation_id" text NOT NULL,
	"wake_turn_index" integer NOT NULL,
	"scorer" text NOT NULL,
	"score" real NOT NULL,
	"rationale" text,
	"model" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agents"."agent_staff_memory" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"staff_id" text NOT NULL,
	"memory" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agents"."learned_skills" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"agent_id" text,
	"name" text NOT NULL,
	"description" text NOT NULL,
	"body" text NOT NULL,
	"tags" text[] DEFAULT '{}'::text[] NOT NULL,
	"version" integer DEFAULT 1,
	"parent_proposal_id" text,
	"threat_scan_report" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "agents"."learning_candidates" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"conversation_id" text NOT NULL,
	"signal_kind" text NOT NULL,
	"signal_ref" text NOT NULL,
	"triage_confidence" double precision NOT NULL,
	"scope_hint" text,
	"summary" text NOT NULL,
	"context" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"consumed_by_proposal_id" text,
	"dismissed_reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "learning_candidates_status_check" CHECK (status IN ('pending','consumed','dismissed','expired')),
	CONSTRAINT "learning_candidates_signal_kind_check" CHECK (signal_kind IN ('staff_takeover','coexistence_echo','coaching_note','rejection','self_reflection','manual'))
);
--> statement-breakpoint
CREATE TABLE "agents"."operator_thread_messages" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"thread_id" text NOT NULL,
	"seq" integer NOT NULL,
	"role" text NOT NULL,
	"content" text DEFAULT '' NOT NULL,
	"payload" jsonb DEFAULT '{}' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "operator_thread_messages_role_check" CHECK (role IN ('user', 'assistant', 'system', 'tool'))
);
--> statement-breakpoint
CREATE TABLE "agents"."operator_threads" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"created_by" text NOT NULL,
	"title" text,
	"status" text DEFAULT 'open' NOT NULL,
	"last_turn_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "operator_threads_status_check" CHECK (status IN ('open', 'closed', 'archived'))
);
--> statement-breakpoint
CREATE TABLE "automations"."automation_rules" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"slug" text NOT NULL,
	"cron" text NOT NULL,
	"timezone" text DEFAULT 'UTC' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"config" jsonb,
	"last_tick_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "automation_rules_cron_check" CHECK (length(cron) <= 64)
);
--> statement-breakpoint
CREATE TABLE "automations"."automation_runs" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"rule_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"event_name" text NOT NULL,
	"status" text NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone,
	"duration_ms" integer,
	"error_message" text,
	"payload_snapshot" jsonb,
	"wake_id" text,
	CONSTRAINT "automation_runs_status_check" CHECK (status IN ('queued','succeeded','failed','suppressed_cooldown','suppressed_paused','suppressed_budget','suppressed_unverified'))
);
--> statement-breakpoint
CREATE TABLE "automations"."automations" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"event_name" text NOT NULL,
	"action" jsonb NOT NULL,
	"paused" boolean DEFAULT false NOT NULL,
	"paused_reason" text,
	"paused_at" timestamp with time zone,
	"cron" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "automations_action_type_check" CHECK (action->>'type' IN ('wake', 'webhook'))
);
--> statement-breakpoint
CREATE TABLE "automations"."tenant_budget_caps" (
	"organization_id" text PRIMARY KEY,
	"daily_cap_usd" integer NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "changes"."change_history" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"resource_module" text NOT NULL,
	"resource_type" text NOT NULL,
	"resource_id" text NOT NULL,
	"payload" jsonb NOT NULL,
	"before" jsonb,
	"after" jsonb,
	"changed_by" text NOT NULL,
	"changed_by_kind" text NOT NULL,
	"applied_proposal_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "change_history_kind_check" CHECK (changed_by_kind IN ('user','agent'))
);
--> statement-breakpoint
CREATE TABLE "changes"."change_proposals" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"resource_module" text NOT NULL,
	"resource_type" text NOT NULL,
	"resource_id" text NOT NULL,
	"payload" jsonb NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"confidence" real,
	"rationale" text,
	"expected_outcome" text,
	"conversation_id" text,
	"proposed_by_id" text NOT NULL,
	"proposed_by_kind" text NOT NULL,
	"decided_by_user_id" text,
	"decided_at" timestamp with time zone,
	"decided_note" text,
	"applied_history_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "change_proposals_status_check" CHECK (status IN ('pending','approved','rejected','auto_written','superseded')),
	CONSTRAINT "change_proposals_kind_check" CHECK (proposed_by_kind IN ('user','agent'))
);
--> statement-breakpoint
CREATE TABLE "channels"."channel_instances" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"channel" text NOT NULL,
	"role" text DEFAULT 'customer' NOT NULL,
	"display_name" text,
	"config" jsonb DEFAULT '{}' NOT NULL,
	"platform_channel_id" text GENERATED ALWAYS AS ((config->>'platformChannelId')) STORED,
	"webhook_secret" text,
	"status" text DEFAULT 'active',
	"setup_stage" text,
	"last_error" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "channel_instances_role_check" CHECK (role IN ('customer','staff'))
);
--> statement-breakpoint
CREATE TABLE "channels"."channels" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"name" text NOT NULL UNIQUE,
	"enabled" boolean DEFAULT true NOT NULL,
	"capabilities" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "channels"."conversation_sessions" (
	"conversation_id" text PRIMARY KEY,
	"channel_instance_id" text NOT NULL,
	"session_state" text DEFAULT 'open' NOT NULL,
	"window_opened_at" timestamp with time zone NOT NULL,
	"window_expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "channels"."signup_nonces" (
	"nonce" text PRIMARY KEY,
	"organization_id" text NOT NULL,
	"session_id" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "channels"."whatsapp_history_chunks" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"channel_instance_id" text NOT NULL,
	"phase" integer NOT NULL,
	"chunk_order" integer NOT NULL,
	"progress" integer DEFAULT 0 NOT NULL,
	"phone_number_id" text DEFAULT '' NOT NULL,
	"declined" boolean DEFAULT false NOT NULL,
	"payload" jsonb NOT NULL,
	"processed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "contacts"."contact_attribute_definitions" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"key" text NOT NULL,
	"label" text NOT NULL,
	"type" text DEFAULT 'text' NOT NULL,
	"options" text[] DEFAULT '{}'::text[] NOT NULL,
	"show_in_table" boolean DEFAULT false NOT NULL,
	"sensitivity" text DEFAULT 'medium' NOT NULL,
	"sort_order" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "contact_attr_def_type_check" CHECK (type IN ('text','number','boolean','date','enum')),
	CONSTRAINT "contact_attr_def_sensitivity_check" CHECK (sensitivity IN ('low','medium','high','critical'))
);
--> statement-breakpoint
CREATE TABLE "contacts"."contact_external_keys" (
	"organization_id" text,
	"channel" text,
	"external_key" text,
	"contact_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "contact_external_keys_pkey" PRIMARY KEY("organization_id","channel","external_key")
);
--> statement-breakpoint
CREATE TABLE "contacts"."contacts" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"display_name" text,
	"phone" text,
	"email" text,
	"profile" text DEFAULT '' NOT NULL,
	"memory" text DEFAULT '' NOT NULL,
	"attributes" jsonb DEFAULT '{}' NOT NULL,
	"segments" text[] DEFAULT '{}'::text[] NOT NULL,
	"marketing_opt_out" boolean DEFAULT false NOT NULL,
	"marketing_opt_out_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "contacts"."staff_channel_bindings" (
	"user_id" text,
	"channel_instance_id" text,
	"external_identifier" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "staff_channel_bindings_pkey" PRIMARY KEY("user_id","channel_instance_id")
);
--> statement-breakpoint
CREATE TABLE "drive"."chunks" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"scope" text NOT NULL,
	"scope_id" text NOT NULL,
	"file_id" text NOT NULL,
	"chunk_index" integer NOT NULL,
	"content" text NOT NULL,
	"embedding" vector(1536),
	"token_count" integer DEFAULT 0 NOT NULL,
	"tsv" tsvector GENERATED ALWAYS AS (to_tsvector('english', content)) STORED,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "drive"."files" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"scope" text NOT NULL,
	"scope_id" text NOT NULL,
	"parent_folder_id" text,
	"kind" text NOT NULL,
	"name" text NOT NULL,
	"path" text NOT NULL,
	"mime_type" text,
	"size_bytes" integer,
	"storage_key" text,
	"caption" text,
	"caption_model" text,
	"caption_updated_at" timestamp with time zone,
	"extracted_text" text,
	"original_name" text,
	"name_stem" text,
	"source" text,
	"source_message_id" text,
	"tags" text[] DEFAULT '{}'::text[] NOT NULL,
	"uploaded_by" text,
	"processing_status" text DEFAULT 'ready',
	"extraction_kind" text DEFAULT 'pending' NOT NULL,
	"processing_error" text,
	"threat_scan_report" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "drive_kind_check" CHECK (kind IN ('folder','file')),
	CONSTRAINT "drive_scope_check" CHECK (scope IN ('organization','contact','staff','agent')),
	CONSTRAINT "drive_source_check" CHECK (source IS NULL OR source IN ('customer_inbound','agent_uploaded','staff_uploaded','admin_uploaded')),
	CONSTRAINT "drive_extraction_kind_check" CHECK (extraction_kind IN ('pending','extracted','binary-stub','failed'))
);
--> statement-breakpoint
CREATE TABLE "integrations"."secrets" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"provider" text NOT NULL,
	"routine_secret_envelope" text NOT NULL,
	"rotation_key_envelope" text NOT NULL,
	"key_version" integer DEFAULT 1 NOT NULL,
	"routine_secret_previous_envelope" text,
	"rotation_key_previous_envelope" text,
	"previous_key_version" integer,
	"previous_valid_until" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "messaging"."conversations" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"contact_id" text NOT NULL,
	"channel_instance_id" text NOT NULL,
	"status" text NOT NULL,
	"assignee" text NOT NULL,
	"owner_user_id" text,
	"owner_assigned_at" timestamp with time zone,
	"thread_key" text DEFAULT 'default' NOT NULL,
	"email_subject" text,
	"snoozed_until" timestamp with time zone,
	"snoozed_reason" text,
	"snoozed_by" text,
	"snoozed_at" timestamp with time zone,
	"snoozed_job_id" text,
	"last_message_at" timestamp with time zone,
	"resolved_at" timestamp with time zone,
	"resolved_reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "conversations_status_check" CHECK (status IN ('active','resolving','awaiting_approval','resolved','failed'))
);
--> statement-breakpoint
CREATE TABLE "messaging"."internal_notes" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"conversation_id" text NOT NULL,
	"author_type" text NOT NULL,
	"author_id" text NOT NULL,
	"body" text NOT NULL,
	"mentions" text[] DEFAULT '{}'::text[] NOT NULL,
	"parent_note_id" text,
	"notif_channel_msg_id" text,
	"notif_channel_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "internal_notes_author_type_check" CHECK (author_type IN ('agent','staff','system'))
);
--> statement-breakpoint
CREATE TABLE "messaging"."mention_dismissals" (
	"user_id" text NOT NULL,
	"note_id" text NOT NULL,
	"dismissed_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "messaging"."message_reactions" (
	"message_id" text,
	"channel_instance_id" text NOT NULL,
	"reactor_external_id" text,
	"emoji" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "message_reactions_pkey" PRIMARY KEY("message_id","reactor_external_id","emoji")
);
--> statement-breakpoint
CREATE TABLE "messaging"."messages" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"conversation_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"role" text NOT NULL,
	"kind" text NOT NULL,
	"content" jsonb NOT NULL,
	"parent_message_id" text,
	"channel_external_id" text,
	"status" text,
	"attachments" jsonb DEFAULT '[]' NOT NULL,
	"metadata" jsonb DEFAULT '{}' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "messages_role_check" CHECK (role IN ('customer','agent','system','staff')),
	CONSTRAINT "messages_kind_check" CHECK (kind IN ('text','image','card','card_reply'))
);
--> statement-breakpoint
CREATE TABLE "messaging"."pending_approvals" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"conversation_id" text,
	"conversation_event_id" text,
	"tool_name" text NOT NULL,
	"tool_args" jsonb NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"decided_by_user_id" text,
	"decided_at" timestamp with time zone,
	"decided_note" text,
	"agent_snapshot" jsonb,
	"wake_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "pending_approvals_status_check" CHECK (status IN ('pending','approved','rejected','expired'))
);
--> statement-breakpoint
CREATE TABLE "settings"."org_settings" (
	"organization_id" text NOT NULL,
	"key" text NOT NULL,
	"value" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "settings"."user_notification_prefs" (
	"user_id" text PRIMARY KEY,
	"prefs" jsonb DEFAULT '{}' NOT NULL,
	"notify_while_online" boolean DEFAULT false NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "team"."pending_staff_pings" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"conversation_id" text NOT NULL,
	"staff_user_id" text NOT NULL,
	"asking_agent_id" text NOT NULL,
	"original_note_id" text NOT NULL,
	"outbound_wamid" text,
	"kind" text DEFAULT 'mention' NOT NULL,
	"reference_id" text,
	"claimed_at" timestamp with time zone,
	"claimed_wamid" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "team"."routing_rules" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"kind" text NOT NULL,
	"keyword" text,
	"pool" text,
	"rep_user_id" text,
	"priority" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "routing_rules_kind_check" CHECK (kind IN ('exclusive','pool_keyword','pool_member'))
);
--> statement-breakpoint
CREATE TABLE "team"."staff_attribute_definitions" (
	"id" text PRIMARY KEY DEFAULT nanoid(8),
	"organization_id" text NOT NULL,
	"key" text NOT NULL,
	"label" text NOT NULL,
	"type" text DEFAULT 'text' NOT NULL,
	"options" text[] DEFAULT '{}'::text[] NOT NULL,
	"show_in_table" boolean DEFAULT false NOT NULL,
	"sort_order" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "staff_attr_def_type_check" CHECK (type IN ('text','number','boolean','date','enum'))
);
--> statement-breakpoint
CREATE TABLE "team"."staff_profiles" (
	"user_id" text PRIMARY KEY,
	"organization_id" text NOT NULL,
	"display_name" text,
	"title" text,
	"sectors" text[] DEFAULT '{}'::text[] NOT NULL,
	"expertise" text[] DEFAULT '{}'::text[] NOT NULL,
	"languages" text[] DEFAULT '{}'::text[] NOT NULL,
	"capacity" integer DEFAULT 10 NOT NULL,
	"availability" text DEFAULT 'active' NOT NULL,
	"attributes" jsonb DEFAULT '{}' NOT NULL,
	"profile" text DEFAULT '' NOT NULL,
	"memory" text DEFAULT '' NOT NULL,
	"last_seen_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "staff_profiles_availability_check" CHECK (availability IN ('active','busy','off','inactive')),
	CONSTRAINT "staff_profiles_capacity_check" CHECK (capacity >= 0)
);
--> statement-breakpoint
CREATE TABLE "team"."team_descriptions" (
	"team_id" text PRIMARY KEY,
	"organization_id" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"lead_user_id" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "audit_log_event_idx" ON "audit"."audit_log" ("event");--> statement-breakpoint
CREATE INDEX "audit_log_actor_id_idx" ON "audit"."audit_log" ("actor_id");--> statement-breakpoint
CREATE INDEX "audit_log_created_at_idx" ON "audit"."audit_log" ("created_at");--> statement-breakpoint
CREATE INDEX "record_audits_table_record_idx" ON "audit"."record_audits" ("table_name","record_id");--> statement-breakpoint
CREATE INDEX "record_audits_changed_by_idx" ON "audit"."record_audits" ("changed_by");--> statement-breakpoint
CREATE INDEX "record_audits_created_at_idx" ON "audit"."record_audits" ("created_at");--> statement-breakpoint
CREATE INDEX "channels_log_channel_idx" ON "infra"."channels_log" ("channel");--> statement-breakpoint
CREATE INDEX "channels_log_direction_idx" ON "infra"."channels_log" ("direction");--> statement-breakpoint
CREATE INDEX "channels_log_status_idx" ON "infra"."channels_log" ("status");--> statement-breakpoint
CREATE INDEX "channels_templates_channel_idx" ON "infra"."channels_templates" ("channel");--> statement-breakpoint
CREATE INDEX "channels_templates_name_idx" ON "infra"."channels_templates" ("name");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_agent_msg_seq" ON "harness"."messages" ("thread_id","seq");--> statement-breakpoint
CREATE INDEX "idx_agent_msg_thread" ON "harness"."messages" ("thread_id","seq");--> statement-breakpoint
CREATE INDEX "idx_audit_wake_map_wake" ON "harness"."audit_wake_map" ("wake_id");--> statement-breakpoint
CREATE INDEX "idx_audit_wake_map_conv" ON "harness"."audit_wake_map" ("conversation_id");--> statement-breakpoint
CREATE INDEX "idx_convev_conv" ON "harness"."conversation_events" ("conversation_id","ts");--> statement-breakpoint
CREATE INDEX "idx_convev_type_ts" ON "harness"."conversation_events" ("type","ts");--> statement-breakpoint
CREATE INDEX "idx_convev_wake" ON "harness"."conversation_events" ("wake_id") WHERE "wake_id" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_convev_llm_task" ON "harness"."conversation_events" ("llm_task","ts") WHERE "llm_task" IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_pending_approvals_call" ON "harness"."pending_approvals" ("wake_id","tool_call_id");--> statement-breakpoint
CREATE INDEX "idx_pending_approvals_status" ON "harness"."pending_approvals" ("status","expires_at");--> statement-breakpoint
CREATE INDEX "idx_pending_approvals_conv" ON "harness"."pending_approvals" ("conversation_id","requested_at");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_thread_conv" ON "harness"."threads" ("agent_id","conversation_id") WHERE "conversation_id" IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_thread_cron" ON "harness"."threads" ("agent_id","cron_key") WHERE "cron_key" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_thread_agent" ON "harness"."threads" ("agent_id");--> statement-breakpoint
CREATE INDEX "integrations_provider_idx" ON "infra"."integrations" ("provider");--> statement-breakpoint
CREATE INDEX "integrations_status_idx" ON "infra"."integrations" ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "integrations_active_platform_provider_idx" ON "infra"."integrations" ("provider") WHERE status = 'active' AND auth_type = 'platform';--> statement-breakpoint
CREATE INDEX "rate_limits_key_hit_at_idx" ON "infra"."rate_limits" ("key","hit_at");--> statement-breakpoint
CREATE UNIQUE INDEX "storage_objects_bucket_key_idx" ON "infra"."storage_objects" ("bucket","key");--> statement-breakpoint
CREATE INDEX "storage_objects_bucket_idx" ON "infra"."storage_objects" ("bucket");--> statement-breakpoint
CREATE INDEX "storage_objects_uploaded_by_idx" ON "infra"."storage_objects" ("uploaded_by");--> statement-breakpoint
CREATE INDEX "webhook_dedup_received_at_idx" ON "infra"."webhook_dedup" ("received_at");--> statement-breakpoint
CREATE INDEX "account_userId_idx" ON "auth"."account" ("user_id");--> statement-breakpoint
CREATE INDEX "apikey_configId_idx" ON "auth"."apikey" ("config_id");--> statement-breakpoint
CREATE INDEX "apikey_referenceId_idx" ON "auth"."apikey" ("reference_id");--> statement-breakpoint
CREATE INDEX "apikey_key_idx" ON "auth"."apikey" ("key");--> statement-breakpoint
CREATE INDEX "invitation_organizationId_idx" ON "auth"."invitation" ("organization_id");--> statement-breakpoint
CREATE INDEX "invitation_email_idx" ON "auth"."invitation" ("email");--> statement-breakpoint
CREATE INDEX "member_organizationId_idx" ON "auth"."member" ("organization_id");--> statement-breakpoint
CREATE INDEX "member_userId_idx" ON "auth"."member" ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "organization_slug_uidx" ON "auth"."organization" ("slug");--> statement-breakpoint
CREATE INDEX "session_userId_idx" ON "auth"."session" ("user_id");--> statement-breakpoint
CREATE INDEX "team_organizationId_idx" ON "auth"."team" ("organization_id");--> statement-breakpoint
CREATE INDEX "teamMember_teamId_idx" ON "auth"."team_member" ("team_id");--> statement-breakpoint
CREATE INDEX "teamMember_userId_idx" ON "auth"."team_member" ("user_id");--> statement-breakpoint
CREATE INDEX "verification_identifier_idx" ON "auth"."verification" ("identifier");--> statement-breakpoint
CREATE INDEX "agent_definitions_org_enabled_idx" ON "agents"."agent_definitions" ("organization_id") WHERE enabled = true;--> statement-breakpoint
CREATE INDEX "idx_scores_conv" ON "agents"."agent_scores" ("conversation_id","wake_turn_index");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_agent_staff_memory" ON "agents"."agent_staff_memory" ("organization_id","agent_id","staff_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_learned_skills_name" ON "agents"."learned_skills" ("organization_id","agent_id","name");--> statement-breakpoint
CREATE INDEX "idx_learning_candidates_pending" ON "agents"."learning_candidates" ("organization_id","agent_id","conversation_id","status") WHERE status = 'pending';--> statement-breakpoint
CREATE INDEX "idx_learning_candidates_status_age" ON "agents"."learning_candidates" ("status","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_operator_thread_messages_seq" ON "agents"."operator_thread_messages" ("thread_id","seq");--> statement-breakpoint
CREATE INDEX "idx_operator_thread_messages_thread" ON "agents"."operator_thread_messages" ("thread_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_operator_threads_creator" ON "agents"."operator_threads" ("organization_id","created_by","last_turn_at");--> statement-breakpoint
CREATE INDEX "idx_operator_threads_agent" ON "agents"."operator_threads" ("agent_id","last_turn_at");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_automation_rules_slug" ON "automations"."automation_rules" ("organization_id","agent_id","slug");--> statement-breakpoint
CREATE INDEX "idx_automation_rules_enabled" ON "automations"."automation_rules" ("enabled","organization_id");--> statement-breakpoint
CREATE INDEX "idx_automation_runs_rule" ON "automations"."automation_runs" ("rule_id","started_at");--> statement-breakpoint
CREATE INDEX "idx_automation_runs_org" ON "automations"."automation_runs" ("organization_id","started_at");--> statement-breakpoint
CREATE INDEX "idx_automation_runs_status" ON "automations"."automation_runs" ("status","started_at");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_automations_org_name" ON "automations"."automations" ("organization_id","name");--> statement-breakpoint
CREATE INDEX "idx_automations_event_paused" ON "automations"."automations" ("event_name","paused");--> statement-breakpoint
CREATE INDEX "idx_change_history_resource" ON "changes"."change_history" ("resource_module","resource_type","resource_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_change_proposals_inbox" ON "changes"."change_proposals" ("organization_id","status","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "uniq_change_proposals_pending_target" ON "changes"."change_proposals" ("organization_id","resource_module","resource_type","resource_id") WHERE status = 'pending';--> statement-breakpoint
CREATE INDEX "idx_channel_instances_organization" ON "channels"."channel_instances" ("organization_id");--> statement-breakpoint
CREATE INDEX "idx_channel_instances_channel" ON "channels"."channel_instances" ("channel");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_channel_instances_managed_platform_id" ON "channels"."channel_instances" ("organization_id","channel","platform_channel_id") WHERE platform_channel_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_conv_sessions_expires" ON "channels"."conversation_sessions" ("window_expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_wa_history_chunk" ON "channels"."whatsapp_history_chunks" ("channel_instance_id","phase","chunk_order");--> statement-breakpoint
CREATE INDEX "idx_wa_history_chunk_unprocessed" ON "channels"."whatsapp_history_chunks" ("channel_instance_id","processed_at");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_contact_attr_def_org_key" ON "contacts"."contact_attribute_definitions" ("organization_id","key");--> statement-breakpoint
CREATE INDEX "idx_contact_attr_def_org" ON "contacts"."contact_attribute_definitions" ("organization_id");--> statement-breakpoint
CREATE INDEX "idx_contact_external_keys_contact" ON "contacts"."contact_external_keys" ("contact_id");--> statement-breakpoint
CREATE INDEX "idx_contacts_organization" ON "contacts"."contacts" ("organization_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_contacts_tenant_phone" ON "contacts"."contacts" ("organization_id","phone");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_contacts_tenant_email" ON "contacts"."contacts" ("organization_id","email");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_staff_binding_channel_ext" ON "contacts"."staff_channel_bindings" ("channel_instance_id","external_identifier");--> statement-breakpoint
CREATE INDEX "idx_drive_chunks_scope" ON "drive"."chunks" ("organization_id","scope","scope_id");--> statement-breakpoint
CREATE INDEX "idx_drive_chunks_file" ON "drive"."chunks" ("file_id");--> statement-breakpoint
CREATE INDEX "idx_drive_chunks_hnsw" ON "drive"."chunks" USING hnsw ("embedding" vector_cosine_ops);--> statement-breakpoint
CREATE INDEX "idx_drive_chunks_tsv" ON "drive"."chunks" USING gin ("tsv");--> statement-breakpoint
CREATE INDEX "idx_drive_scope_path" ON "drive"."files" ("organization_id","scope","scope_id","path");--> statement-breakpoint
CREATE INDEX "idx_drive_parent" ON "drive"."files" ("parent_folder_id") WHERE "parent_folder_id" IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_drive_path" ON "drive"."files" ("organization_id","scope","scope_id","path");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_drive_parent_name" ON "drive"."files" ("organization_id","scope","scope_id","parent_folder_id","name");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_integration_secrets_org_provider" ON "integrations"."secrets" ("organization_id","provider");--> statement-breakpoint
CREATE INDEX "idx_integration_secrets_provider" ON "integrations"."secrets" ("provider");--> statement-breakpoint
CREATE INDEX "idx_conv_organization_status" ON "messaging"."conversations" ("organization_id","status");--> statement-breakpoint
CREATE INDEX "idx_conv_contact" ON "messaging"."conversations" ("contact_id");--> statement-breakpoint
CREATE INDEX "idx_conv_owner" ON "messaging"."conversations" ("organization_id","owner_user_id","owner_assigned_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_conv_one_per_pair" ON "messaging"."conversations" ("organization_id","contact_id","channel_instance_id","thread_key");--> statement-breakpoint
CREATE INDEX "idx_conv_snoozed" ON "messaging"."conversations" ("organization_id","snoozed_until") WHERE "snoozed_until" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_notes_conv" ON "messaging"."internal_notes" ("conversation_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_notes_notif" ON "messaging"."internal_notes" ("notif_channel_msg_id") WHERE "notif_channel_msg_id" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_notes_mentions" ON "messaging"."internal_notes" USING gin ("mentions");--> statement-breakpoint
CREATE INDEX "idx_mention_dismissals_user" ON "messaging"."mention_dismissals" ("user_id","dismissed_at");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_mention_dismissals" ON "messaging"."mention_dismissals" ("user_id","note_id");--> statement-breakpoint
CREATE INDEX "idx_msg_conv_ts" ON "messaging"."messages" ("conversation_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_msg_channel_ext" ON "messaging"."messages" ("organization_id","channel_external_id") WHERE "channel_external_id" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_pending_conv" ON "messaging"."pending_approvals" ("conversation_id","status");--> statement-breakpoint
CREATE INDEX "idx_pending_wake" ON "messaging"."pending_approvals" ("wake_id") WHERE "wake_id" IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_org_settings_org_key" ON "settings"."org_settings" ("organization_id","key");--> statement-breakpoint
CREATE INDEX "idx_pending_staff_pings_staff" ON "team"."pending_staff_pings" ("staff_user_id","organization_id");--> statement-breakpoint
CREATE INDEX "idx_pending_staff_pings_created" ON "team"."pending_staff_pings" ("created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_pending_staff_pings_conv_staff" ON "team"."pending_staff_pings" ("organization_id","conversation_id","staff_user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_pending_staff_pings_wamid" ON "team"."pending_staff_pings" ("outbound_wamid") WHERE "outbound_wamid" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_pending_staff_pings_live" ON "team"."pending_staff_pings" ("staff_user_id","organization_id") WHERE "claimed_at" IS NULL;--> statement-breakpoint
CREATE INDEX "idx_routing_rules_org" ON "team"."routing_rules" ("organization_id");--> statement-breakpoint
CREATE INDEX "idx_routing_rules_pool" ON "team"."routing_rules" ("organization_id","pool");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_routing_rules_keyword" ON "team"."routing_rules" ("organization_id","keyword") WHERE keyword IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_staff_attr_def_org_key" ON "team"."staff_attribute_definitions" ("organization_id","key");--> statement-breakpoint
CREATE INDEX "idx_staff_attr_def_org" ON "team"."staff_attribute_definitions" ("organization_id");--> statement-breakpoint
CREATE INDEX "idx_staff_profiles_org" ON "team"."staff_profiles" ("organization_id");--> statement-breakpoint
CREATE INDEX "idx_staff_profiles_sectors" ON "team"."staff_profiles" USING gin ("sectors");--> statement-breakpoint
CREATE INDEX "idx_staff_profiles_expertise" ON "team"."staff_profiles" USING gin ("expertise");--> statement-breakpoint
CREATE INDEX "idx_staff_profiles_languages" ON "team"."staff_profiles" USING gin ("languages");--> statement-breakpoint
CREATE INDEX "idx_team_descriptions_org" ON "team"."team_descriptions" ("organization_id");--> statement-breakpoint
ALTER TABLE "harness"."messages" ADD CONSTRAINT "messages_thread_id_threads_id_fkey" FOREIGN KEY ("thread_id") REFERENCES "harness"."threads"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."account" ADD CONSTRAINT "account_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."invitation" ADD CONSTRAINT "invitation_organization_id_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "auth"."organization"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."invitation" ADD CONSTRAINT "invitation_inviter_id_user_id_fkey" FOREIGN KEY ("inviter_id") REFERENCES "auth"."user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."member" ADD CONSTRAINT "member_organization_id_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "auth"."organization"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."member" ADD CONSTRAINT "member_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."session" ADD CONSTRAINT "session_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."team" ADD CONSTRAINT "team_organization_id_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "auth"."organization"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."team_member" ADD CONSTRAINT "team_member_team_id_team_id_fkey" FOREIGN KEY ("team_id") REFERENCES "auth"."team"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."team_member" ADD CONSTRAINT "team_member_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "agents"."agent_staff_memory" ADD CONSTRAINT "agent_staff_memory_agent_id_agent_definitions_id_fkey" FOREIGN KEY ("agent_id") REFERENCES "agents"."agent_definitions"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "agents"."learned_skills" ADD CONSTRAINT "learned_skills_agent_id_agent_definitions_id_fkey" FOREIGN KEY ("agent_id") REFERENCES "agents"."agent_definitions"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "agents"."operator_thread_messages" ADD CONSTRAINT "operator_thread_messages_thread_id_operator_threads_id_fkey" FOREIGN KEY ("thread_id") REFERENCES "agents"."operator_threads"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "agents"."operator_threads" ADD CONSTRAINT "operator_threads_agent_id_agent_definitions_id_fkey" FOREIGN KEY ("agent_id") REFERENCES "agents"."agent_definitions"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."internal_notes" ADD CONSTRAINT "internal_notes_conversation_id_conversations_id_fkey" FOREIGN KEY ("conversation_id") REFERENCES "messaging"."conversations"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."mention_dismissals" ADD CONSTRAINT "mention_dismissals_note_id_internal_notes_id_fkey" FOREIGN KEY ("note_id") REFERENCES "messaging"."internal_notes"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."message_reactions" ADD CONSTRAINT "message_reactions_message_id_messages_id_fkey" FOREIGN KEY ("message_id") REFERENCES "messaging"."messages"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."messages" ADD CONSTRAINT "messages_conversation_id_conversations_id_fkey" FOREIGN KEY ("conversation_id") REFERENCES "messaging"."conversations"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."pending_approvals" ADD CONSTRAINT "pending_approvals_conversation_id_conversations_id_fkey" FOREIGN KEY ("conversation_id") REFERENCES "messaging"."conversations"("id") ON DELETE CASCADE;