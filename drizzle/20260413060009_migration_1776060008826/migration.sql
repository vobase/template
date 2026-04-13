-- Fixtures entry point
-- Use --!include to include SQL files with glob support
-- Run `bun run db:push` to apply during development
-- Run `bun run db:generate` to bake into a migration

-- Extensions
/*
 * Copyright 2025 Viascom Ltd liab. Co
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

-- The `nanoid()` function generates a compact, URL-friendly unique identifier.
-- Based on the given size and alphabet, it creates a randomized string that's ideal for
-- use-cases requiring small, unpredictable IDs (e.g., URL shorteners, generated file names, etc.).
-- While it comes with a default configuration, the function is designed to be flexible,
-- allowing for customization to meet specific needs.
CREATE OR REPLACE FUNCTION nanoid(
    size int DEFAULT 21, -- The number of symbols in the NanoId String. Must be greater than 0.
    alphabet text DEFAULT '0123456789abcdefghijklmnopqrstuvwxyz', -- The symbols used in the NanoId String. Must contain between 1 and 255 symbols.
    additionalBytesFactor float DEFAULT 1.6 -- The additional bytes factor used for calculating the step size. Must be equal or greater then 1.
)
    RETURNS text -- A randomly generated NanoId String
    LANGUAGE plpgsql
    VOLATILE
    PARALLEL SAFE
    -- Uncomment the following line if you have superuser privileges
    -- LEAKPROOF
AS
$$
DECLARE
    alphabetArray  text[];
    alphabetLength int := 64;
    mask           int := 63;
    step           int := 34;
BEGIN
    IF size IS NULL OR size < 1 THEN
        RAISE EXCEPTION 'The size must be defined and greater than 0!';
    END IF;

    IF alphabet IS NULL OR length(alphabet) = 0 OR length(alphabet) > 255 THEN
        RAISE EXCEPTION 'The alphabet can''t be undefined, zero or bigger than 255 symbols!';
    END IF;

    IF additionalBytesFactor IS NULL OR additionalBytesFactor < 1 THEN
        RAISE EXCEPTION 'The additional bytes factor can''t be less than 1!';
    END IF;

    alphabetArray := regexp_split_to_array(alphabet, '');
    alphabetLength := array_length(alphabetArray, 1);
    mask := (2 << cast(floor(log(alphabetLength - 1) / log(2)) as int)) - 1;
    step := cast(ceil(additionalBytesFactor * mask * size / alphabetLength) AS int);

    IF step > 1024 THEN
        step := 1024; -- The step size % can''t be bigger then 1024!
    END IF;

    RETURN nanoid_optimized(size, alphabet, mask, step);
END
$$;

-- Generates an optimized random string of a specified size using the given alphabet, mask, and step.
-- This optimized version is designed for higher performance and lower memory overhead.
-- No checks are performed! Use it only if you really know what you are doing.
CREATE OR REPLACE FUNCTION nanoid_optimized(
    size int, -- The desired length of the generated string.
    alphabet text, -- The set of characters to choose from for generating the string.
    mask int, -- The mask used for mapping random bytes to alphabet indices. Should be `(2^n) - 1` where `n` is a power of 2 less than or equal to the alphabet size.
    step int -- The number of random bytes to generate in each iteration. A larger value may speed up the function but increase memory usage.
)
    RETURNS text -- A randomly generated NanoId String
    LANGUAGE plpgsql
    VOLATILE
    PARALLEL SAFE
    -- Uncomment the following line if you have superuser privileges
    -- LEAKPROOF
AS
$$
DECLARE
    idBuilder      text := '';
    counter        int  := 0;
    bytes          bytea;
    alphabetIndex  int;
    alphabetArray  text[];
    alphabetLength int  := 64;
BEGIN
    alphabetArray := regexp_split_to_array(alphabet, '');
    alphabetLength := array_length(alphabetArray, 1);

    LOOP
        bytes := gen_random_bytes(step);
        FOR counter IN 0..step - 1
            LOOP
                alphabetIndex := (get_byte(bytes, counter) & mask) + 1;
                IF alphabetIndex <= alphabetLength THEN
                    idBuilder := idBuilder || alphabetArray[alphabetIndex];
                    IF length(idBuilder) = size THEN
                        RETURN idBuilder;
                    END IF;
                END IF;
            END LOOP;
    END LOOP;
END
$$;

CREATE EXTENSION IF NOT EXISTS vector;


CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- Functions


-- Triggers


CREATE SCHEMA "audit";
--> statement-breakpoint
CREATE SCHEMA "auth";
--> statement-breakpoint
CREATE SCHEMA "infra";
--> statement-breakpoint
CREATE SCHEMA "agents";
--> statement-breakpoint
CREATE SCHEMA "automation";
--> statement-breakpoint
CREATE SCHEMA "kb";
--> statement-breakpoint
CREATE SCHEMA "messaging";
--> statement-breakpoint
CREATE TABLE "audit"."audit_log" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"event" text NOT NULL,
	"actor_id" text,
	"actor_email" text,
	"ip" text,
	"details" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit"."record_audits" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"table_name" text NOT NULL,
	"record_id" text NOT NULL,
	"old_data" text,
	"new_data" text,
	"changed_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
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
	"refill_interval" text,
	"refill_amount" integer,
	"last_refill_at" timestamp with time zone,
	"enabled" boolean DEFAULT true NOT NULL,
	"rate_limit_enabled" boolean DEFAULT false NOT NULL,
	"rate_limit_time_window" integer DEFAULT 86400000,
	"rate_limit_max" integer DEFAULT 10,
	"request_count" integer DEFAULT 0 NOT NULL,
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
	"email" text NOT NULL,
	"organization_id" text NOT NULL,
	"inviter_id" text NOT NULL,
	"role" text DEFAULT 'member' NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"team_id" text,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth"."member" (
	"id" text PRIMARY KEY,
	"user_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"role" text DEFAULT 'member' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth"."organization" (
	"id" text PRIMARY KEY,
	"name" text NOT NULL,
	"slug" text NOT NULL UNIQUE,
	"logo" text,
	"metadata" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
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
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth"."team_member" (
	"id" text PRIMARY KEY,
	"team_id" text NOT NULL,
	"user_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth"."user" (
	"id" text PRIMARY KEY,
	"name" text NOT NULL,
	"email" text NOT NULL UNIQUE,
	"email_verified" boolean DEFAULT false NOT NULL,
	"image" text,
	"role" text DEFAULT 'user' NOT NULL,
	"is_anonymous" boolean DEFAULT false,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
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
CREATE TABLE "infra"."channels_log" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
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
	"id" text PRIMARY KEY DEFAULT nanoid(12),
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
CREATE TABLE "infra"."integrations" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
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
CREATE TABLE "infra"."sequences" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"prefix" text NOT NULL UNIQUE,
	"current_value" integer DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "infra"."storage_objects" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
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
CREATE TABLE "agents"."moderation_logs" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"agent_id" text NOT NULL,
	"channel" text NOT NULL,
	"user_id" text,
	"contact_id" text,
	"thread_id" text,
	"reason" text NOT NULL,
	"blocked_content" text,
	"matched_term" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "automation"."pairing_codes" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"code" text NOT NULL,
	"user_id" text NOT NULL,
	"session_id" text,
	"status" text DEFAULT 'active' NOT NULL,
	"api_key" text,
	"api_key_id" text,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "pairing_codes_status_check" CHECK (status IN ('active', 'used', 'expired'))
);
--> statement-breakpoint
CREATE TABLE "automation"."sessions" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"user_id" text NOT NULL,
	"status" text DEFAULT 'pairing' NOT NULL,
	"browser_info" jsonb,
	"api_key_id" text,
	"last_heartbeat" timestamp with time zone,
	"paired_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sessions_status_check" CHECK (status IN ('pairing', 'active', 'disconnected', 'expired'))
);
--> statement-breakpoint
CREATE TABLE "automation"."tasks" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"session_id" text,
	"adapter_id" text NOT NULL,
	"action" text NOT NULL,
	"input" jsonb NOT NULL,
	"output" jsonb,
	"status" text DEFAULT 'pending' NOT NULL,
	"assigned_to" text,
	"requires_approval" boolean DEFAULT true NOT NULL,
	"approved_at" timestamp with time zone,
	"approved_by" text,
	"dom_snapshot" text,
	"error_message" text,
	"requested_by" text NOT NULL,
	"source_conversation_id" text,
	"timeout_minutes" integer DEFAULT 10 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tasks_status_check" CHECK (status IN ('pending', 'executing', 'completed', 'failed', 'timeout', 'cancelled')),
	CONSTRAINT "tasks_requested_by_check" CHECK (requested_by IN ('ai', 'staff', 'system'))
);
--> statement-breakpoint
CREATE TABLE "kb"."chunks" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"document_id" text NOT NULL,
	"content" text NOT NULL,
	"chunk_index" integer NOT NULL,
	"token_count" integer DEFAULT 0 NOT NULL,
	"metadata" text,
	"embedding" vector(1536),
	"search_vector" tsvector GENERATED ALWAYS AS (to_tsvector('english', content)) STORED,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "kb"."documents" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"title" text NOT NULL,
	"source_type" text DEFAULT 'upload' NOT NULL,
	"source_id" text,
	"source_url" text,
	"mime_type" text DEFAULT 'text/plain' NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"chunk_count" integer DEFAULT 0 NOT NULL,
	"metadata" text,
	"content" jsonb,
	"raw_content" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "documents_status_check" CHECK (status IN ('pending', 'processing', 'ready', 'error', 'needs_ocr')),
	CONSTRAINT "documents_source_type_check" CHECK (source_type IN ('upload', 'crawl', 'google-drive', 'sharepoint'))
);
--> statement-breakpoint
CREATE TABLE "kb"."sources" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"name" text NOT NULL,
	"type" text NOT NULL,
	"config" text,
	"sync_schedule" text,
	"last_sync_at" timestamp with time zone,
	"status" text DEFAULT 'idle' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sources_type_check" CHECK (type IN ('crawl', 'google-drive', 'sharepoint')),
	CONSTRAINT "sources_status_check" CHECK (status IN ('idle', 'syncing', 'error'))
);
--> statement-breakpoint
CREATE TABLE "kb"."sync_logs" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"source_id" text NOT NULL,
	"status" text NOT NULL,
	"documents_processed" integer DEFAULT 0 NOT NULL,
	"errors" text,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	CONSTRAINT "sync_logs_status_check" CHECK (status IN ('running', 'completed', 'error'))
);
--> statement-breakpoint
CREATE TABLE "messaging"."channel_instance_teams" (
	"channel_instance_id" text,
	"team_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "channel_instance_teams_pkey" PRIMARY KEY("channel_instance_id","team_id")
);
--> statement-breakpoint
CREATE TABLE "messaging"."channel_instances" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"type" text NOT NULL,
	"integration_id" text,
	"label" text NOT NULL,
	"source" text NOT NULL,
	"config" jsonb DEFAULT '{}',
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "channel_instances_source_check" CHECK (source IN ('env', 'self', 'platform', 'sandbox')),
	CONSTRAINT "channel_instances_status_check" CHECK (status IN ('active', 'disconnected', 'error'))
);
--> statement-breakpoint
CREATE TABLE "messaging"."channel_routings" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"name" text NOT NULL,
	"channel_instance_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"assignment_pattern" text DEFAULT 'direct' NOT NULL,
	"config" jsonb DEFAULT '{}',
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "channel_routings_assignment_check" CHECK (assignment_pattern IN ('direct', 'router', 'workflow'))
);
--> statement-breakpoint
CREATE TABLE "messaging"."channel_sessions" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"conversation_id" text NOT NULL,
	"channel_instance_id" text NOT NULL,
	"channel_type" text NOT NULL,
	"session_state" text DEFAULT 'window_open' NOT NULL,
	"window_opens_at" timestamp with time zone DEFAULT now() NOT NULL,
	"window_expires_at" timestamp with time zone NOT NULL,
	"metadata" jsonb DEFAULT '{}',
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "channel_sessions_state_check" CHECK (session_state IN ('window_open', 'window_expired'))
);
--> statement-breakpoint
CREATE TABLE "messaging"."contact_labels" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"contact_id" text NOT NULL,
	"label_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "messaging"."contacts" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"phone" text UNIQUE,
	"email" text UNIQUE,
	"name" text,
	"identifier" text UNIQUE,
	"role" text DEFAULT 'customer' NOT NULL,
	"metadata" jsonb DEFAULT '{}',
	"working_memory" text,
	"resource_metadata" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "contacts_role_check" CHECK (role IN ('customer', 'lead', 'staff'))
);
--> statement-breakpoint
CREATE TABLE "messaging"."conversation_labels" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"conversation_id" text NOT NULL,
	"label_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "messaging"."conversation_participants" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"conversation_id" text NOT NULL,
	"contact_id" text NOT NULL,
	"role" text DEFAULT 'initiator' NOT NULL,
	"joined_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "conversation_participants_role_check" CHECK (role IN ('initiator', 'participant', 'cc', 'bcc'))
);
--> statement-breakpoint
CREATE TABLE "messaging"."conversations" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"channel_routing_id" text,
	"contact_id" text NOT NULL,
	"agent_id" text NOT NULL,
	"channel_instance_id" text NOT NULL,
	"title" text,
	"status" text DEFAULT 'active' NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"resolved_at" timestamp with time zone,
	"outcome" text,
	"autonomy_level" text,
	"reopen_count" integer DEFAULT 0 NOT NULL,
	"metadata" jsonb DEFAULT '{}',
	"assignee" text NOT NULL,
	"assigned_at" timestamp with time zone,
	"on_hold" boolean DEFAULT false NOT NULL,
	"held_at" timestamp with time zone,
	"hold_reason" text,
	"priority" text,
	"custom_attributes" jsonb DEFAULT '{}',
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "conversations_status_check" CHECK (status IN ('active', 'resolving', 'resolved', 'failed')),
	CONSTRAINT "conversations_priority_check" CHECK (priority IS NULL OR priority IN ('low', 'normal', 'high', 'urgent')),
	CONSTRAINT "conversations_outcome_check" CHECK (outcome IS NULL OR outcome IN ('resolved', 'escalated', 'abandoned', 'topic_change')),
	CONSTRAINT "conversations_autonomy_level_check" CHECK (autonomy_level IS NULL OR autonomy_level IN ('full_ai', 'ai_with_escalation', 'human_assisted', 'human_only'))
);
--> statement-breakpoint
CREATE TABLE "messaging"."labels" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"title" text NOT NULL UNIQUE,
	"color" text,
	"description" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "messaging"."message_feedback" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"conversation_id" text NOT NULL,
	"message_id" text NOT NULL,
	"rating" text NOT NULL,
	"reason" text,
	"user_id" text,
	"contact_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "message_feedback_rating_check" CHECK (rating IN ('positive', 'negative')),
	CONSTRAINT "message_feedback_actor_check" CHECK (user_id IS NOT NULL OR contact_id IS NOT NULL)
);
--> statement-breakpoint
CREATE TABLE "messaging"."messages" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"conversation_id" text NOT NULL,
	"message_type" text NOT NULL,
	"content_type" text NOT NULL,
	"content" text NOT NULL,
	"content_data" jsonb DEFAULT '{}',
	"mastra_content" jsonb,
	"status" text,
	"failure_reason" text,
	"sender_id" text NOT NULL,
	"sender_type" text NOT NULL,
	"retry_count" integer DEFAULT 0 NOT NULL,
	"external_message_id" text,
	"channel_type" text,
	"private" boolean DEFAULT false NOT NULL,
	"withdrawn" boolean DEFAULT false NOT NULL,
	"reply_to_message_id" text,
	"resolution_status" text,
	"mentions" jsonb DEFAULT '[]',
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "messages_type_check" CHECK (message_type IN ('incoming', 'outgoing', 'activity')),
	CONSTRAINT "messages_content_type_check" CHECK (content_type IN ('text', 'image', 'document', 'audio', 'video', 'template', 'interactive', 'sticker', 'email', 'system')),
	CONSTRAINT "messages_sender_type_check" CHECK (sender_type IN ('contact', 'user', 'agent', 'system')),
	CONSTRAINT "messages_status_check" CHECK (status IS NULL OR status IN ('queued', 'sent', 'delivered', 'read', 'failed')),
	CONSTRAINT "messages_resolution_status_check" CHECK (resolution_status IS NULL OR resolution_status IN ('pending', 'reviewed', 'dismissed'))
);
--> statement-breakpoint
CREATE TABLE "messaging"."reactions" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"message_id" text NOT NULL,
	"conversation_id" text NOT NULL,
	"user_id" text,
	"contact_id" text,
	"emoji" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "reactions_actor_check" CHECK (user_id IS NOT NULL OR contact_id IS NOT NULL)
);
--> statement-breakpoint
CREATE INDEX "audit_log_event_idx" ON "audit"."audit_log" ("event");--> statement-breakpoint
CREATE INDEX "audit_log_actor_id_idx" ON "audit"."audit_log" ("actor_id");--> statement-breakpoint
CREATE INDEX "audit_log_created_at_idx" ON "audit"."audit_log" ("created_at");--> statement-breakpoint
CREATE INDEX "record_audits_table_record_idx" ON "audit"."record_audits" ("table_name","record_id");--> statement-breakpoint
CREATE INDEX "record_audits_changed_by_idx" ON "audit"."record_audits" ("changed_by");--> statement-breakpoint
CREATE INDEX "record_audits_created_at_idx" ON "audit"."record_audits" ("created_at");--> statement-breakpoint
CREATE INDEX "account_user_id_idx" ON "auth"."account" ("user_id");--> statement-breakpoint
CREATE INDEX "apikey_reference_id_idx" ON "auth"."apikey" ("reference_id");--> statement-breakpoint
CREATE INDEX "apikey_key_idx" ON "auth"."apikey" ("key");--> statement-breakpoint
CREATE INDEX "apikey_config_id_idx" ON "auth"."apikey" ("config_id");--> statement-breakpoint
CREATE INDEX "invitation_org_id_idx" ON "auth"."invitation" ("organization_id");--> statement-breakpoint
CREATE INDEX "invitation_inviter_id_idx" ON "auth"."invitation" ("inviter_id");--> statement-breakpoint
CREATE INDEX "invitation_email_idx" ON "auth"."invitation" ("email");--> statement-breakpoint
CREATE INDEX "member_user_id_idx" ON "auth"."member" ("user_id");--> statement-breakpoint
CREATE INDEX "member_org_id_idx" ON "auth"."member" ("organization_id");--> statement-breakpoint
CREATE UNIQUE INDEX "member_user_org_unique_idx" ON "auth"."member" ("user_id","organization_id");--> statement-breakpoint
CREATE INDEX "session_user_id_idx" ON "auth"."session" ("user_id");--> statement-breakpoint
CREATE INDEX "session_expires_at_idx" ON "auth"."session" ("expires_at");--> statement-breakpoint
CREATE INDEX "team_org_id_idx" ON "auth"."team" ("organization_id");--> statement-breakpoint
CREATE INDEX "team_member_team_id_idx" ON "auth"."team_member" ("team_id");--> statement-breakpoint
CREATE INDEX "team_member_user_id_idx" ON "auth"."team_member" ("user_id");--> statement-breakpoint
CREATE INDEX "verification_identifier_idx" ON "auth"."verification" ("identifier");--> statement-breakpoint
CREATE INDEX "channels_log_channel_idx" ON "infra"."channels_log" ("channel");--> statement-breakpoint
CREATE INDEX "channels_log_direction_idx" ON "infra"."channels_log" ("direction");--> statement-breakpoint
CREATE INDEX "channels_log_status_idx" ON "infra"."channels_log" ("status");--> statement-breakpoint
CREATE INDEX "channels_templates_channel_idx" ON "infra"."channels_templates" ("channel");--> statement-breakpoint
CREATE INDEX "channels_templates_name_idx" ON "infra"."channels_templates" ("name");--> statement-breakpoint
CREATE INDEX "integrations_provider_idx" ON "infra"."integrations" ("provider");--> statement-breakpoint
CREATE INDEX "integrations_status_idx" ON "infra"."integrations" ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "integrations_active_platform_provider_idx" ON "infra"."integrations" ("provider") WHERE status = 'active' AND auth_type = 'platform';--> statement-breakpoint
CREATE UNIQUE INDEX "storage_objects_bucket_key_idx" ON "infra"."storage_objects" ("bucket","key");--> statement-breakpoint
CREATE INDEX "storage_objects_bucket_idx" ON "infra"."storage_objects" ("bucket");--> statement-breakpoint
CREATE INDEX "storage_objects_uploaded_by_idx" ON "infra"."storage_objects" ("uploaded_by");--> statement-breakpoint
CREATE INDEX "webhook_dedup_received_at_idx" ON "infra"."webhook_dedup" ("received_at");--> statement-breakpoint
CREATE INDEX "moderation_logs_created_idx" ON "agents"."moderation_logs" ("created_at");--> statement-breakpoint
CREATE INDEX "moderation_logs_agent_created_idx" ON "agents"."moderation_logs" ("agent_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "pairing_codes_code_unique_idx" ON "automation"."pairing_codes" ("code");--> statement-breakpoint
CREATE INDEX "sessions_user_id_idx" ON "automation"."sessions" ("user_id");--> statement-breakpoint
CREATE INDEX "sessions_status_idx" ON "automation"."sessions" ("status");--> statement-breakpoint
CREATE INDEX "tasks_status_idx" ON "automation"."tasks" ("status");--> statement-breakpoint
CREATE INDEX "tasks_assigned_to_idx" ON "automation"."tasks" ("assigned_to");--> statement-breakpoint
CREATE INDEX "tasks_session_id_idx" ON "automation"."tasks" ("session_id");--> statement-breakpoint
CREATE INDEX "chunks_document_id_idx" ON "kb"."chunks" ("document_id");--> statement-breakpoint
CREATE INDEX "chunks_embedding_idx" ON "kb"."chunks" USING hnsw ("embedding" vector_cosine_ops);--> statement-breakpoint
CREATE INDEX "chunks_search_vector_idx" ON "kb"."chunks" USING gin ("search_vector");--> statement-breakpoint
CREATE INDEX "documents_source_id_idx" ON "kb"."documents" ("source_id");--> statement-breakpoint
CREATE INDEX "documents_pending_idx" ON "kb"."documents" ("status") WHERE status IN ('pending', 'processing');--> statement-breakpoint
CREATE INDEX "sources_status_idx" ON "kb"."sources" ("status");--> statement-breakpoint
CREATE INDEX "sync_logs_source_id_idx" ON "kb"."sync_logs" ("source_id");--> statement-breakpoint
CREATE INDEX "channel_instances_type_idx" ON "messaging"."channel_instances" ("type");--> statement-breakpoint
CREATE INDEX "channel_instances_status_idx" ON "messaging"."channel_instances" ("status");--> statement-breakpoint
CREATE INDEX "channel_instances_integration_idx" ON "messaging"."channel_instances" ("integration_id");--> statement-breakpoint
CREATE INDEX "channel_routings_channel_instance_idx" ON "messaging"."channel_routings" ("channel_instance_id");--> statement-breakpoint
CREATE INDEX "channel_routings_agent_id_idx" ON "messaging"."channel_routings" ("agent_id");--> statement-breakpoint
CREATE UNIQUE INDEX "channel_sessions_conv_instance_unique" ON "messaging"."channel_sessions" ("conversation_id","channel_instance_id");--> statement-breakpoint
CREATE INDEX "channel_sessions_expiry_idx" ON "messaging"."channel_sessions" ("session_state","window_expires_at") WHERE session_state = 'window_open';--> statement-breakpoint
CREATE UNIQUE INDEX "contact_labels_unique_idx" ON "messaging"."contact_labels" ("contact_id","label_id");--> statement-breakpoint
CREATE INDEX "contacts_phone_idx" ON "messaging"."contacts" ("phone");--> statement-breakpoint
CREATE INDEX "contacts_email_idx" ON "messaging"."contacts" ("email");--> statement-breakpoint
CREATE INDEX "contacts_role_idx" ON "messaging"."contacts" ("role");--> statement-breakpoint
CREATE UNIQUE INDEX "conversation_labels_unique_idx" ON "messaging"."conversation_labels" ("conversation_id","label_id");--> statement-breakpoint
CREATE UNIQUE INDEX "conversation_participants_unique_idx" ON "messaging"."conversation_participants" ("conversation_id","contact_id");--> statement-breakpoint
CREATE UNIQUE INDEX "conversations_contact_channel_unique" ON "messaging"."conversations" ("contact_id","channel_instance_id") WHERE status IN ('active', 'resolving');--> statement-breakpoint
CREATE INDEX "conversations_contact_id_idx" ON "messaging"."conversations" ("contact_id");--> statement-breakpoint
CREATE INDEX "conversations_agent_id_idx" ON "messaging"."conversations" ("agent_id");--> statement-breakpoint
CREATE INDEX "conversations_status_idx" ON "messaging"."conversations" ("status");--> statement-breakpoint
CREATE INDEX "conversations_channel_routing_id_idx" ON "messaging"."conversations" ("channel_routing_id");--> statement-breakpoint
CREATE INDEX "conversations_channel_instance_idx" ON "messaging"."conversations" ("channel_instance_id");--> statement-breakpoint
CREATE INDEX "conversations_active_stale_idx" ON "messaging"."conversations" ("status","updated_at") WHERE status = 'active';--> statement-breakpoint
CREATE INDEX "idx_conv_assignee_status" ON "messaging"."conversations" ("assignee","status");--> statement-breakpoint
CREATE INDEX "idx_conv_resolved" ON "messaging"."conversations" ("status","updated_at");--> statement-breakpoint
CREATE INDEX "idx_conv_reopen" ON "messaging"."conversations" ("contact_id","channel_instance_id","status","resolved_at");--> statement-breakpoint
CREATE INDEX "message_feedback_conversation_idx" ON "messaging"."message_feedback" ("conversation_id");--> statement-breakpoint
CREATE INDEX "message_feedback_message_idx" ON "messaging"."message_feedback" ("message_id");--> statement-breakpoint
CREATE UNIQUE INDEX "message_feedback_reaction_unique_idx" ON "messaging"."message_feedback" ("conversation_id","message_id","user_id","contact_id") WHERE reason IS NULL;--> statement-breakpoint
CREATE INDEX "idx_messages_conversation_created" ON "messaging"."messages" ("conversation_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_messages_external_id_unique" ON "messaging"."messages" ("external_message_id") WHERE external_message_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "idx_messages_pending_delivery" ON "messaging"."messages" ("conversation_id","status") WHERE status = 'queued';--> statement-breakpoint
CREATE INDEX "idx_messages_type_created" ON "messaging"."messages" ("message_type","created_at");--> statement-breakpoint
CREATE INDEX "idx_messages_sender" ON "messaging"."messages" ("sender_id");--> statement-breakpoint
CREATE INDEX "idx_messages_pending_attention" ON "messaging"."messages" ("resolution_status") WHERE resolution_status = 'pending';--> statement-breakpoint
CREATE INDEX "idx_messages_mentions" ON "messaging"."messages" USING gin (mentions jsonb_path_ops);--> statement-breakpoint
CREATE UNIQUE INDEX "reactions_unique_idx" ON "messaging"."reactions" ("message_id","user_id","contact_id","emoji");--> statement-breakpoint
ALTER TABLE "auth"."account" ADD CONSTRAINT "account_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."invitation" ADD CONSTRAINT "invitation_organization_id_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "auth"."organization"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."invitation" ADD CONSTRAINT "invitation_inviter_id_user_id_fkey" FOREIGN KEY ("inviter_id") REFERENCES "auth"."user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."member" ADD CONSTRAINT "member_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."member" ADD CONSTRAINT "member_organization_id_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "auth"."organization"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."session" ADD CONSTRAINT "session_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."team" ADD CONSTRAINT "team_organization_id_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "auth"."organization"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."team_member" ADD CONSTRAINT "team_member_team_id_team_id_fkey" FOREIGN KEY ("team_id") REFERENCES "auth"."team"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "auth"."team_member" ADD CONSTRAINT "team_member_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "automation"."pairing_codes" ADD CONSTRAINT "pairing_codes_session_id_sessions_id_fkey" FOREIGN KEY ("session_id") REFERENCES "automation"."sessions"("id");--> statement-breakpoint
ALTER TABLE "automation"."tasks" ADD CONSTRAINT "tasks_session_id_sessions_id_fkey" FOREIGN KEY ("session_id") REFERENCES "automation"."sessions"("id");--> statement-breakpoint
ALTER TABLE "kb"."chunks" ADD CONSTRAINT "chunks_document_id_documents_id_fkey" FOREIGN KEY ("document_id") REFERENCES "kb"."documents"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "kb"."documents" ADD CONSTRAINT "documents_source_id_sources_id_fkey" FOREIGN KEY ("source_id") REFERENCES "kb"."sources"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "kb"."sync_logs" ADD CONSTRAINT "sync_logs_source_id_sources_id_fkey" FOREIGN KEY ("source_id") REFERENCES "kb"."sources"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."channel_instance_teams" ADD CONSTRAINT "channel_instance_teams_pu1sOuIKfED1_fkey" FOREIGN KEY ("channel_instance_id") REFERENCES "messaging"."channel_instances"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."channel_routings" ADD CONSTRAINT "channel_routings_channel_instance_id_channel_instances_id_fkey" FOREIGN KEY ("channel_instance_id") REFERENCES "messaging"."channel_instances"("id");--> statement-breakpoint
ALTER TABLE "messaging"."channel_sessions" ADD CONSTRAINT "channel_sessions_conversation_id_conversations_id_fkey" FOREIGN KEY ("conversation_id") REFERENCES "messaging"."conversations"("id");--> statement-breakpoint
ALTER TABLE "messaging"."channel_sessions" ADD CONSTRAINT "channel_sessions_channel_instance_id_channel_instances_id_fkey" FOREIGN KEY ("channel_instance_id") REFERENCES "messaging"."channel_instances"("id");--> statement-breakpoint
ALTER TABLE "messaging"."contact_labels" ADD CONSTRAINT "contact_labels_contact_id_contacts_id_fkey" FOREIGN KEY ("contact_id") REFERENCES "messaging"."contacts"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."contact_labels" ADD CONSTRAINT "contact_labels_label_id_labels_id_fkey" FOREIGN KEY ("label_id") REFERENCES "messaging"."labels"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."conversation_labels" ADD CONSTRAINT "conversation_labels_conversation_id_conversations_id_fkey" FOREIGN KEY ("conversation_id") REFERENCES "messaging"."conversations"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."conversation_labels" ADD CONSTRAINT "conversation_labels_label_id_labels_id_fkey" FOREIGN KEY ("label_id") REFERENCES "messaging"."labels"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."conversation_participants" ADD CONSTRAINT "conversation_participants_conversation_id_conversations_id_fkey" FOREIGN KEY ("conversation_id") REFERENCES "messaging"."conversations"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."conversation_participants" ADD CONSTRAINT "conversation_participants_contact_id_contacts_id_fkey" FOREIGN KEY ("contact_id") REFERENCES "messaging"."contacts"("id");--> statement-breakpoint
ALTER TABLE "messaging"."conversations" ADD CONSTRAINT "conversations_channel_routing_id_channel_routings_id_fkey" FOREIGN KEY ("channel_routing_id") REFERENCES "messaging"."channel_routings"("id");--> statement-breakpoint
ALTER TABLE "messaging"."conversations" ADD CONSTRAINT "conversations_contact_id_contacts_id_fkey" FOREIGN KEY ("contact_id") REFERENCES "messaging"."contacts"("id");--> statement-breakpoint
ALTER TABLE "messaging"."conversations" ADD CONSTRAINT "conversations_channel_instance_id_channel_instances_id_fkey" FOREIGN KEY ("channel_instance_id") REFERENCES "messaging"."channel_instances"("id");--> statement-breakpoint
ALTER TABLE "messaging"."message_feedback" ADD CONSTRAINT "message_feedback_conversation_id_conversations_id_fkey" FOREIGN KEY ("conversation_id") REFERENCES "messaging"."conversations"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."messages" ADD CONSTRAINT "messages_conversation_id_conversations_id_fkey" FOREIGN KEY ("conversation_id") REFERENCES "messaging"."conversations"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "messaging"."reactions" ADD CONSTRAINT "reactions_conversation_id_conversations_id_fkey" FOREIGN KEY ("conversation_id") REFERENCES "messaging"."conversations"("id") ON DELETE CASCADE;