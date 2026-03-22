-- Fixtures entry point
-- Use --!include to include SQL files with glob support
-- Run `bun run db:push` to apply during development
-- Run `bun run db:generate` to bake into a migration

-- Extensions
CREATE EXTENSION IF NOT EXISTS vector;


CREATE EXTENSION IF NOT EXISTS pgcrypto;


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
DROP FUNCTION IF EXISTS nanoid(int, text, float);
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
DROP FUNCTION IF EXISTS nanoid_optimized(int, text, int, int);
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

-- Functions


-- Triggers


CREATE TABLE "_audit_log" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"event" text NOT NULL,
	"actor_id" text,
	"actor_email" text,
	"ip" text,
	"details" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "_record_audits" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"table_name" text NOT NULL,
	"record_id" text NOT NULL,
	"old_data" text,
	"new_data" text,
	"changed_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "account" (
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
CREATE TABLE "apikey" (
	"id" text PRIMARY KEY,
	"name" text,
	"start" text,
	"prefix" text,
	"key" text NOT NULL,
	"user_id" text NOT NULL,
	"refill_interval" text,
	"refill_amount" integer,
	"last_refill_at" timestamp with time zone,
	"enabled" boolean DEFAULT true NOT NULL,
	"rate_limit_enabled" boolean DEFAULT false NOT NULL,
	"rate_limit_time_window" integer,
	"rate_limit_max" integer,
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
CREATE TABLE "invitation" (
	"id" text PRIMARY KEY,
	"email" text NOT NULL,
	"organization_id" text NOT NULL,
	"inviter_id" text NOT NULL,
	"role" text DEFAULT 'member' NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "member" (
	"id" text PRIMARY KEY,
	"user_id" text NOT NULL,
	"organization_id" text NOT NULL,
	"role" text DEFAULT 'member' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "organization" (
	"id" text PRIMARY KEY,
	"name" text NOT NULL,
	"slug" text NOT NULL UNIQUE,
	"logo" text,
	"metadata" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "session" (
	"id" text PRIMARY KEY,
	"expires_at" timestamp with time zone NOT NULL,
	"token" text NOT NULL UNIQUE,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ip_address" text,
	"user_agent" text,
	"user_id" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user" (
	"id" text PRIMARY KEY,
	"name" text NOT NULL,
	"email" text NOT NULL UNIQUE,
	"email_verified" boolean DEFAULT false NOT NULL,
	"image" text,
	"role" text DEFAULT 'user' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "verification" (
	"id" text PRIMARY KEY,
	"identifier" text NOT NULL,
	"value" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "_channels_log" (
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
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "_channels_templates" (
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
CREATE TABLE "_integrations" (
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
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "_sequences" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"prefix" text NOT NULL UNIQUE,
	"current_value" integer DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "_storage_objects" (
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
CREATE TABLE "_webhook_dedup" (
	"id" text,
	"source" text,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "_webhook_dedup_pkey" PRIMARY KEY("id","source")
);
--> statement-breakpoint
CREATE TABLE "ai_eval_runs" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"agent_id" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"results" text,
	"error_message" text,
	"item_count" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "msg_mem_cells" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"thread_id" text NOT NULL,
	"contact_id" text,
	"user_id" text,
	"start_message_id" text NOT NULL,
	"end_message_id" text NOT NULL,
	"message_count" integer NOT NULL,
	"token_count" integer NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"error_message" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "msg_mem_episodes" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"cell_id" text NOT NULL,
	"contact_id" text,
	"user_id" text,
	"title" text NOT NULL,
	"content" text NOT NULL,
	"embedding" vector(1536),
	"search_vector" tsvector GENERATED ALWAYS AS (to_tsvector('english', title || ' ' || content)) STORED,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "msg_mem_event_logs" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"cell_id" text NOT NULL,
	"contact_id" text,
	"user_id" text,
	"fact" text NOT NULL,
	"subject" text,
	"occurred_at" timestamp with time zone,
	"embedding" vector(1536),
	"search_vector" tsvector GENERATED ALWAYS AS (to_tsvector('english', fact)) STORED,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ai_moderation_logs" (
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
CREATE TABLE "ai_workflow_runs" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"workflow_id" text NOT NULL,
	"user_id" text NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"input_data" text NOT NULL,
	"suspend_payload" text,
	"output_data" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "kb_chunks" (
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
CREATE TABLE "kb_documents" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"title" text NOT NULL,
	"source_type" text DEFAULT 'upload' NOT NULL,
	"source_id" text,
	"source_url" text,
	"mime_type" text DEFAULT 'text/plain' NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"chunk_count" integer DEFAULT 0 NOT NULL,
	"metadata" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "kb_sources" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"name" text NOT NULL,
	"type" text NOT NULL,
	"config" text,
	"sync_schedule" text,
	"last_sync_at" timestamp with time zone,
	"status" text DEFAULT 'idle' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "kb_sync_logs" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"source_id" text NOT NULL,
	"status" text NOT NULL,
	"documents_processed" integer DEFAULT 0 NOT NULL,
	"errors" text,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "msg_contacts" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"phone" text UNIQUE,
	"email" text UNIQUE,
	"name" text,
	"channel" text,
	"metadata" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "msg_outbox" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"thread_id" text NOT NULL,
	"content" text NOT NULL,
	"channel" text DEFAULT 'web' NOT NULL,
	"external_message_id" text UNIQUE,
	"status" text DEFAULT 'queued' NOT NULL,
	"retry_count" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "msg_threads" (
	"id" text PRIMARY KEY DEFAULT nanoid(12),
	"title" text,
	"agent_id" text,
	"user_id" text,
	"contact_id" text,
	"channel" text DEFAULT 'web' NOT NULL,
	"status" text DEFAULT 'ai' NOT NULL,
	"ai_paused_at" timestamp with time zone,
	"ai_resume_at" timestamp with time zone,
	"window_expires_at" timestamp with time zone,
	"archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "account_user_id_idx" ON "account" ("user_id");--> statement-breakpoint
CREATE INDEX "session_user_id_idx" ON "session" ("user_id");--> statement-breakpoint
CREATE INDEX "verification_identifier_idx" ON "verification" ("identifier");--> statement-breakpoint
CREATE INDEX "channels_log_channel_idx" ON "_channels_log" ("channel");--> statement-breakpoint
CREATE INDEX "channels_log_direction_idx" ON "_channels_log" ("direction");--> statement-breakpoint
CREATE INDEX "channels_log_status_idx" ON "_channels_log" ("status");--> statement-breakpoint
CREATE INDEX "channels_templates_channel_idx" ON "_channels_templates" ("channel");--> statement-breakpoint
CREATE INDEX "channels_templates_name_idx" ON "_channels_templates" ("name");--> statement-breakpoint
CREATE INDEX "integrations_provider_idx" ON "_integrations" ("provider");--> statement-breakpoint
CREATE INDEX "integrations_status_idx" ON "_integrations" ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "storage_objects_bucket_key_idx" ON "_storage_objects" ("bucket","key");--> statement-breakpoint
CREATE INDEX "storage_objects_bucket_idx" ON "_storage_objects" ("bucket");--> statement-breakpoint
CREATE INDEX "storage_objects_uploaded_by_idx" ON "_storage_objects" ("uploaded_by");--> statement-breakpoint
CREATE INDEX "msg_mem_cells_thread_id_idx" ON "msg_mem_cells" ("thread_id");--> statement-breakpoint
CREATE INDEX "msg_mem_cells_contact_status_idx" ON "msg_mem_cells" ("contact_id","status");--> statement-breakpoint
CREATE INDEX "msg_mem_cells_user_status_idx" ON "msg_mem_cells" ("user_id","status");--> statement-breakpoint
CREATE INDEX "msg_mem_cells_status_idx" ON "msg_mem_cells" ("status");--> statement-breakpoint
CREATE INDEX "msg_mem_episodes_cell_id_idx" ON "msg_mem_episodes" ("cell_id");--> statement-breakpoint
CREATE INDEX "msg_mem_episodes_contact_id_idx" ON "msg_mem_episodes" ("contact_id");--> statement-breakpoint
CREATE INDEX "msg_mem_episodes_user_id_idx" ON "msg_mem_episodes" ("user_id");--> statement-breakpoint
CREATE INDEX "msg_mem_episodes_embedding_idx" ON "msg_mem_episodes" USING hnsw ("embedding" vector_cosine_ops);--> statement-breakpoint
CREATE INDEX "msg_mem_episodes_search_vector_idx" ON "msg_mem_episodes" USING gin ("search_vector");--> statement-breakpoint
CREATE INDEX "msg_mem_event_logs_cell_id_idx" ON "msg_mem_event_logs" ("cell_id");--> statement-breakpoint
CREATE INDEX "msg_mem_event_logs_contact_id_idx" ON "msg_mem_event_logs" ("contact_id");--> statement-breakpoint
CREATE INDEX "msg_mem_event_logs_user_id_idx" ON "msg_mem_event_logs" ("user_id");--> statement-breakpoint
CREATE INDEX "msg_mem_event_logs_subject_idx" ON "msg_mem_event_logs" ("subject");--> statement-breakpoint
CREATE INDEX "msg_mem_event_logs_embedding_idx" ON "msg_mem_event_logs" USING hnsw ("embedding" vector_cosine_ops);--> statement-breakpoint
CREATE INDEX "msg_mem_event_logs_search_vector_idx" ON "msg_mem_event_logs" USING gin ("search_vector");--> statement-breakpoint
CREATE INDEX "ai_moderation_logs_created_idx" ON "ai_moderation_logs" ("created_at");--> statement-breakpoint
CREATE INDEX "ai_moderation_logs_agent_created_idx" ON "ai_moderation_logs" ("agent_id","created_at");--> statement-breakpoint
CREATE INDEX "ai_workflow_runs_wf_created_idx" ON "ai_workflow_runs" ("workflow_id","created_at");--> statement-breakpoint
CREATE INDEX "kb_chunks_document_id_idx" ON "kb_chunks" ("document_id");--> statement-breakpoint
CREATE INDEX "kb_documents_source_id_idx" ON "kb_documents" ("source_id");--> statement-breakpoint
CREATE INDEX "kb_documents_status_idx" ON "kb_documents" ("status");--> statement-breakpoint
CREATE INDEX "kb_sync_logs_source_id_idx" ON "kb_sync_logs" ("source_id");--> statement-breakpoint
CREATE INDEX "msg_outbox_thread_id_idx" ON "msg_outbox" ("thread_id");--> statement-breakpoint
CREATE INDEX "msg_outbox_external_id_idx" ON "msg_outbox" ("external_message_id");--> statement-breakpoint
CREATE INDEX "msg_outbox_status_idx" ON "msg_outbox" ("status");--> statement-breakpoint
CREATE INDEX "msg_threads_user_id_idx" ON "msg_threads" ("user_id");--> statement-breakpoint
CREATE INDEX "msg_threads_agent_id_idx" ON "msg_threads" ("agent_id");--> statement-breakpoint
CREATE INDEX "msg_threads_contact_id_idx" ON "msg_threads" ("contact_id");--> statement-breakpoint
ALTER TABLE "account" ADD CONSTRAINT "account_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "apikey" ADD CONSTRAINT "apikey_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "invitation" ADD CONSTRAINT "invitation_organization_id_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "invitation" ADD CONSTRAINT "invitation_inviter_id_user_id_fkey" FOREIGN KEY ("inviter_id") REFERENCES "user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "member" ADD CONSTRAINT "member_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "member" ADD CONSTRAINT "member_organization_id_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "session" ADD CONSTRAINT "session_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE;