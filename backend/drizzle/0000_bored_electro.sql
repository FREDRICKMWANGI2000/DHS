CREATE TYPE "public"."account_status" AS ENUM('ACTIVE', 'DISABLED');--> statement-breakpoint
CREATE TYPE "public"."message_visibility" AS ENUM('CUSTOMER', 'INTERNAL');--> statement-breakpoint
CREATE TYPE "public"."payment_provider" AS ENUM('MPESA');--> statement-breakpoint
CREATE TYPE "public"."payment_status" AS ENUM('PENDING', 'SUCCESS', 'FAILED', 'CANCELLED', 'REVERSED');--> statement-breakpoint
CREATE TYPE "public"."service_order_status" AS ENUM('DRAFT', 'PAYMENT_PENDING', 'PAID', 'QUEUED', 'IN_PROGRESS', 'WAITING_FOR_CUSTOMER', 'READY', 'COMPLETED', 'CANCELLED', 'REFUNDED');--> statement-breakpoint
CREATE TYPE "public"."service_pricing_unit" AS ENUM('FIXED', 'PER_PAGE', 'PER_HOUR', 'PER_SESSION', 'PER_SET');--> statement-breakpoint
CREATE TYPE "public"."user_role" AS ENUM('CUSTOMER', 'STAFF', 'ADMIN', 'SUPER_ADMIN');--> statement-breakpoint
CREATE TYPE "public"."verification_type" AS ENUM('EMAIL', 'PHONE');--> statement-breakpoint
CREATE TYPE "public"."wifi_session_status" AS ENUM('PENDING_PAYMENT', 'PENDING_AUTHORIZATION', 'ACTIVE', 'EXPIRED', 'REVOKED', 'FAILED');--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"first_name" varchar(100) NOT NULL,
	"last_name" varchar(100) NOT NULL,
	"email" varchar(255),
	"phone_number" varchar(32),
	"password_hash" text NOT NULL,
	"role" "user_role" DEFAULT 'CUSTOMER' NOT NULL,
	"status" "account_status" DEFAULT 'ACTIVE' NOT NULL,
	"email_verified_at" timestamp with time zone,
	"phone_verified_at" timestamp with time zone,
	"last_login_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_contact_required_chk" CHECK ("users"."email" IS NOT NULL OR "users"."phone_number" IS NOT NULL),
	CONSTRAINT "users_email_normalized_chk" CHECK ("users"."email" IS NULL OR ("users"."email" = lower(trim("users"."email")) AND char_length("users"."email") >= 3)),
	CONSTRAINT "users_phone_normalized_chk" CHECK ("users"."phone_number" IS NULL OR ("users"."phone_number" = trim("users"."phone_number") AND "users"."phone_number" ~ '^\+[1-9][0-9]{7,14}$'))
);
--> statement-breakpoint
CREATE TABLE "password_reset_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"token_hash" varchar(128) NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "password_reset_tokens_expires_chk" CHECK ("password_reset_tokens"."expires_at" > "password_reset_tokens"."created_at")
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"token_hash" varchar(128) NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"ip_address" varchar(64),
	"user_agent" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sessions_expires_after_created_chk" CHECK ("sessions"."expires_at" > "sessions"."created_at")
);
--> statement-breakpoint
CREATE TABLE "verification_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"token_hash" varchar(128) NOT NULL,
	"verification_type" "verification_type" NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "verification_tokens_expires_chk" CHECK ("verification_tokens"."expires_at" > "verification_tokens"."created_at")
);
--> statement-breakpoint
CREATE TABLE "audit_logs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"actor_user_id" uuid,
	"action" varchar(120) NOT NULL,
	"entity_type" varchar(80) NOT NULL,
	"entity_id" varchar(128),
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"ip_address" varchar(64),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "customer_devices" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"customer_id" uuid NOT NULL,
	"device_name" varchar(100) NOT NULL,
	"mac_address" varchar(32) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone,
	"is_active" boolean DEFAULT true NOT NULL,
	CONSTRAINT "customer_devices_mac_normalized_chk" CHECK ("customer_devices"."mac_address" = upper(trim("customer_devices"."mac_address")) AND "customer_devices"."mac_address" ~ '^([0-9A-F]{2}:){5}[0-9A-F]{2}$')
);
--> statement-breakpoint
CREATE TABLE "wifi_packages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(100) NOT NULL,
	"slug" varchar(100) NOT NULL,
	"description" text,
	"price" numeric(10, 2) NOT NULL,
	"currency" varchar(3) DEFAULT 'KES' NOT NULL,
	"duration_minutes" integer NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"display_order" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "wifi_packages_price_positive_chk" CHECK ("wifi_packages"."price" > 0),
	CONSTRAINT "wifi_packages_duration_positive_chk" CHECK ("wifi_packages"."duration_minutes" > 0),
	CONSTRAINT "wifi_packages_currency_len_chk" CHECK (char_length("wifi_packages"."currency") = 3)
);
--> statement-breakpoint
CREATE TABLE "wifi_sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"customer_id" uuid,
	"package_id" uuid NOT NULL,
	"package_name_snapshot" varchar(100) NOT NULL,
	"amount_snapshot" numeric(10, 2) NOT NULL,
	"currency" varchar(3) DEFAULT 'KES' NOT NULL,
	"duration_minutes_snapshot" integer NOT NULL,
	"phone_number" varchar(32) NOT NULL,
	"client_mac" varchar(32),
	"client_ip" varchar(64),
	"status" "wifi_session_status" DEFAULT 'PENDING_PAYMENT' NOT NULL,
	"started_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"authorized_at" timestamp with time zone,
	"gateway_reference" varchar(128),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "wifi_sessions_amount_positive_chk" CHECK ("wifi_sessions"."amount_snapshot" > 0),
	CONSTRAINT "wifi_sessions_duration_positive_chk" CHECK ("wifi_sessions"."duration_minutes_snapshot" > 0),
	CONSTRAINT "wifi_sessions_expiry_after_start_chk" CHECK ("wifi_sessions"."expires_at" IS NULL OR "wifi_sessions"."started_at" IS NULL OR "wifi_sessions"."expires_at" > "wifi_sessions"."started_at"),
	CONSTRAINT "wifi_sessions_phone_normalized_chk" CHECK ("wifi_sessions"."phone_number" = trim("wifi_sessions"."phone_number") AND "wifi_sessions"."phone_number" ~ '^\+[1-9][0-9]{7,14}$'),
	CONSTRAINT "wifi_sessions_mac_normalized_chk" CHECK ("wifi_sessions"."client_mac" IS NULL OR ("wifi_sessions"."client_mac" = upper(trim("wifi_sessions"."client_mac")) AND "wifi_sessions"."client_mac" ~ '^([0-9A-F]{2}:){5}[0-9A-F]{2}$'))
);
--> statement-breakpoint
CREATE TABLE "service_catalog" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(150) NOT NULL,
	"slug" varchar(150) NOT NULL,
	"description" text,
	"price" numeric(10, 2) NOT NULL,
	"currency" varchar(3) DEFAULT 'KES' NOT NULL,
	"pricing_unit" "service_pricing_unit" DEFAULT 'FIXED' NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"display_order" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "service_catalog_price_positive_chk" CHECK ("service_catalog"."price" > 0),
	CONSTRAINT "service_catalog_currency_len_chk" CHECK (char_length("service_catalog"."currency") = 3)
);
--> statement-breakpoint
CREATE TABLE "service_order_status_history" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"order_id" uuid NOT NULL,
	"previous_status" "service_order_status",
	"new_status" "service_order_status" NOT NULL,
	"changed_by" uuid,
	"note" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "service_orders" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"order_number" varchar(40) NOT NULL,
	"customer_id" uuid NOT NULL,
	"service_id" uuid NOT NULL,
	"service_name_snapshot" varchar(150) NOT NULL,
	"quantity" integer DEFAULT 1 NOT NULL,
	"unit_price_snapshot" numeric(10, 2) NOT NULL,
	"total_amount" numeric(10, 2) NOT NULL,
	"currency" varchar(3) DEFAULT 'KES' NOT NULL,
	"pricing_unit_snapshot" "service_pricing_unit" NOT NULL,
	"status" "service_order_status" DEFAULT 'DRAFT' NOT NULL,
	"customer_requirements" text,
	"form_data" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	CONSTRAINT "service_orders_quantity_positive_chk" CHECK ("service_orders"."quantity" >= 1),
	CONSTRAINT "service_orders_unit_price_positive_chk" CHECK ("service_orders"."unit_price_snapshot" > 0),
	CONSTRAINT "service_orders_total_amount_chk" CHECK ("service_orders"."total_amount" = "service_orders"."unit_price_snapshot" * "service_orders"."quantity")
);
--> statement-breakpoint
CREATE TABLE "staff_assignments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"order_id" uuid NOT NULL,
	"staff_user_id" uuid NOT NULL,
	"assigned_by" uuid NOT NULL,
	"assigned_at" timestamp with time zone DEFAULT now() NOT NULL,
	"unassigned_at" timestamp with time zone,
	"notes" text,
	CONSTRAINT "staff_assignments_unassigned_after_assigned_chk" CHECK ("staff_assignments"."unassigned_at" IS NULL OR "staff_assignments"."unassigned_at" >= "staff_assignments"."assigned_at")
);
--> statement-breakpoint
CREATE TABLE "payment_attempts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"payment_id" uuid NOT NULL,
	"attempt_number" integer NOT NULL,
	"merchant_request_id" varchar(128),
	"checkout_request_id" varchar(128),
	"mpesa_receipt_number" varchar(64),
	"result_code" varchar(32),
	"result_description" text,
	"status" "payment_status" DEFAULT 'PENDING' NOT NULL,
	"initiated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "payment_attempts_attempt_num_positive_chk" CHECK ("payment_attempts"."attempt_number" >= 1)
);
--> statement-breakpoint
CREATE TABLE "payment_callback_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"payment_attempt_id" uuid NOT NULL,
	"idempotency_key" varchar(160) NOT NULL,
	"provider_event_id" varchar(128),
	"outcome" varchar(64) NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	"processed_at" timestamp with time zone,
	"safe_metadata" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "payments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"reference" varchar(64) NOT NULL,
	"wifi_session_id" uuid,
	"service_order_id" uuid,
	"provider" "payment_provider" DEFAULT 'MPESA' NOT NULL,
	"amount" numeric(10, 2) NOT NULL,
	"currency" varchar(3) DEFAULT 'KES' NOT NULL,
	"status" "payment_status" DEFAULT 'PENDING' NOT NULL,
	"paid_at" timestamp with time zone,
	"reversed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "payments_target_xor_chk" CHECK (("payments"."wifi_session_id" IS NOT NULL AND "payments"."service_order_id" IS NULL) OR ("payments"."wifi_session_id" IS NULL AND "payments"."service_order_id" IS NOT NULL)),
	CONSTRAINT "payments_amount_positive_chk" CHECK ("payments"."amount" > 0),
	CONSTRAINT "payments_currency_len_chk" CHECK (char_length("payments"."currency") = 3)
);
--> statement-breakpoint
CREATE TABLE "service_order_files" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"order_id" uuid NOT NULL,
	"uploaded_by" uuid NOT NULL,
	"original_filename" varchar(255) NOT NULL,
	"storage_key" varchar(512) NOT NULL,
	"mime_type" varchar(128) NOT NULL,
	"file_size" integer NOT NULL,
	"checksum" varchar(128) NOT NULL,
	"is_deliverable" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "service_order_files_size_positive_chk" CHECK ("service_order_files"."file_size" > 0)
);
--> statement-breakpoint
CREATE TABLE "service_order_messages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"order_id" uuid NOT NULL,
	"sender_user_id" uuid NOT NULL,
	"body" text NOT NULL,
	"visibility" "message_visibility" DEFAULT 'CUSTOMER' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "service_order_messages_body_nonempty_chk" CHECK (char_length(trim("service_order_messages"."body")) > 0)
);
--> statement-breakpoint
CREATE TABLE "business_settings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"key" varchar(120) NOT NULL,
	"value" jsonb NOT NULL,
	"description" text,
	"updated_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "password_reset_tokens" ADD CONSTRAINT "password_reset_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "verification_tokens" ADD CONSTRAINT "verification_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "customer_devices" ADD CONSTRAINT "customer_devices_customer_id_users_id_fk" FOREIGN KEY ("customer_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wifi_sessions" ADD CONSTRAINT "wifi_sessions_customer_id_users_id_fk" FOREIGN KEY ("customer_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wifi_sessions" ADD CONSTRAINT "wifi_sessions_package_id_wifi_packages_id_fk" FOREIGN KEY ("package_id") REFERENCES "public"."wifi_packages"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_order_status_history" ADD CONSTRAINT "service_order_status_history_order_id_service_orders_id_fk" FOREIGN KEY ("order_id") REFERENCES "public"."service_orders"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_order_status_history" ADD CONSTRAINT "service_order_status_history_changed_by_users_id_fk" FOREIGN KEY ("changed_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_orders" ADD CONSTRAINT "service_orders_customer_id_users_id_fk" FOREIGN KEY ("customer_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_orders" ADD CONSTRAINT "service_orders_service_id_service_catalog_id_fk" FOREIGN KEY ("service_id") REFERENCES "public"."service_catalog"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "staff_assignments" ADD CONSTRAINT "staff_assignments_order_id_service_orders_id_fk" FOREIGN KEY ("order_id") REFERENCES "public"."service_orders"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "staff_assignments" ADD CONSTRAINT "staff_assignments_staff_user_id_users_id_fk" FOREIGN KEY ("staff_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "staff_assignments" ADD CONSTRAINT "staff_assignments_assigned_by_users_id_fk" FOREIGN KEY ("assigned_by") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payment_attempts" ADD CONSTRAINT "payment_attempts_payment_id_payments_id_fk" FOREIGN KEY ("payment_id") REFERENCES "public"."payments"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payment_callback_events" ADD CONSTRAINT "payment_callback_events_payment_attempt_id_payment_attempts_id_fk" FOREIGN KEY ("payment_attempt_id") REFERENCES "public"."payment_attempts"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payments" ADD CONSTRAINT "payments_wifi_session_id_wifi_sessions_id_fk" FOREIGN KEY ("wifi_session_id") REFERENCES "public"."wifi_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payments" ADD CONSTRAINT "payments_service_order_id_service_orders_id_fk" FOREIGN KEY ("service_order_id") REFERENCES "public"."service_orders"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_order_files" ADD CONSTRAINT "service_order_files_order_id_service_orders_id_fk" FOREIGN KEY ("order_id") REFERENCES "public"."service_orders"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_order_files" ADD CONSTRAINT "service_order_files_uploaded_by_users_id_fk" FOREIGN KEY ("uploaded_by") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_order_messages" ADD CONSTRAINT "service_order_messages_order_id_service_orders_id_fk" FOREIGN KEY ("order_id") REFERENCES "public"."service_orders"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_order_messages" ADD CONSTRAINT "service_order_messages_sender_user_id_users_id_fk" FOREIGN KEY ("sender_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "business_settings" ADD CONSTRAINT "business_settings_updated_by_users_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "users_email_unique" ON "users" USING btree ("email");--> statement-breakpoint
CREATE UNIQUE INDEX "users_phone_number_unique" ON "users" USING btree ("phone_number");--> statement-breakpoint
CREATE INDEX "users_role_status_idx" ON "users" USING btree ("role","status");--> statement-breakpoint
CREATE UNIQUE INDEX "password_reset_tokens_hash_unique" ON "password_reset_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "password_reset_tokens_user_id_idx" ON "password_reset_tokens" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "sessions_token_hash_unique" ON "sessions" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "sessions_user_id_expires_idx" ON "sessions" USING btree ("user_id","expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "verification_tokens_hash_unique" ON "verification_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "verification_tokens_user_type_idx" ON "verification_tokens" USING btree ("user_id","verification_type");--> statement-breakpoint
CREATE INDEX "audit_logs_actor_user_id_idx" ON "audit_logs" USING btree ("actor_user_id");--> statement-breakpoint
CREATE INDEX "audit_logs_entity_idx" ON "audit_logs" USING btree ("entity_type","entity_id");--> statement-breakpoint
CREATE INDEX "audit_logs_created_at_idx" ON "audit_logs" USING btree ("created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "customer_devices_customer_mac_unique" ON "customer_devices" USING btree ("customer_id","mac_address");--> statement-breakpoint
CREATE INDEX "customer_devices_mac_idx" ON "customer_devices" USING btree ("mac_address");--> statement-breakpoint
CREATE UNIQUE INDEX "wifi_packages_slug_unique" ON "wifi_packages" USING btree ("slug");--> statement-breakpoint
CREATE INDEX "wifi_packages_active_order_idx" ON "wifi_packages" USING btree ("is_active","display_order");--> statement-breakpoint
CREATE INDEX "wifi_sessions_customer_id_idx" ON "wifi_sessions" USING btree ("customer_id");--> statement-breakpoint
CREATE INDEX "wifi_sessions_package_id_idx" ON "wifi_sessions" USING btree ("package_id");--> statement-breakpoint
CREATE INDEX "wifi_sessions_status_expires_idx" ON "wifi_sessions" USING btree ("status","expires_at");--> statement-breakpoint
CREATE INDEX "wifi_sessions_phone_number_idx" ON "wifi_sessions" USING btree ("phone_number");--> statement-breakpoint
CREATE INDEX "wifi_sessions_client_mac_idx" ON "wifi_sessions" USING btree ("client_mac");--> statement-breakpoint
CREATE UNIQUE INDEX "service_catalog_slug_unique" ON "service_catalog" USING btree ("slug");--> statement-breakpoint
CREATE INDEX "service_catalog_active_order_idx" ON "service_catalog" USING btree ("is_active","display_order");--> statement-breakpoint
CREATE INDEX "service_order_status_history_order_created_idx" ON "service_order_status_history" USING btree ("order_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "service_orders_order_number_unique" ON "service_orders" USING btree ("order_number");--> statement-breakpoint
CREATE INDEX "service_orders_customer_id_idx" ON "service_orders" USING btree ("customer_id");--> statement-breakpoint
CREATE INDEX "service_orders_service_id_idx" ON "service_orders" USING btree ("service_id");--> statement-breakpoint
CREATE INDEX "service_orders_status_created_idx" ON "service_orders" USING btree ("status","created_at");--> statement-breakpoint
CREATE INDEX "staff_assignments_order_id_idx" ON "staff_assignments" USING btree ("order_id");--> statement-breakpoint
CREATE INDEX "staff_assignments_staff_active_idx" ON "staff_assignments" USING btree ("staff_user_id","unassigned_at");--> statement-breakpoint
CREATE UNIQUE INDEX "payment_attempts_payment_attempt_num_unique" ON "payment_attempts" USING btree ("payment_id","attempt_number");--> statement-breakpoint
CREATE UNIQUE INDEX "payment_attempts_merchant_request_id_unique" ON "payment_attempts" USING btree ("merchant_request_id");--> statement-breakpoint
CREATE UNIQUE INDEX "payment_attempts_checkout_request_id_unique" ON "payment_attempts" USING btree ("checkout_request_id");--> statement-breakpoint
CREATE UNIQUE INDEX "payment_attempts_mpesa_receipt_unique" ON "payment_attempts" USING btree ("mpesa_receipt_number");--> statement-breakpoint
CREATE INDEX "payment_attempts_payment_id_idx" ON "payment_attempts" USING btree ("payment_id");--> statement-breakpoint
CREATE UNIQUE INDEX "payment_callback_events_idempotency_key_unique" ON "payment_callback_events" USING btree ("idempotency_key");--> statement-breakpoint
CREATE UNIQUE INDEX "payment_callback_events_provider_event_id_unique" ON "payment_callback_events" USING btree ("provider_event_id");--> statement-breakpoint
CREATE INDEX "payment_callback_events_attempt_id_idx" ON "payment_callback_events" USING btree ("payment_attempt_id");--> statement-breakpoint
CREATE UNIQUE INDEX "payments_reference_unique" ON "payments" USING btree ("reference");--> statement-breakpoint
CREATE UNIQUE INDEX "payments_wifi_session_id_unique" ON "payments" USING btree ("wifi_session_id");--> statement-breakpoint
CREATE UNIQUE INDEX "payments_service_order_id_unique" ON "payments" USING btree ("service_order_id");--> statement-breakpoint
CREATE INDEX "payments_status_created_idx" ON "payments" USING btree ("status","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "service_order_files_storage_key_unique" ON "service_order_files" USING btree ("storage_key");--> statement-breakpoint
CREATE INDEX "service_order_files_order_id_idx" ON "service_order_files" USING btree ("order_id");--> statement-breakpoint
CREATE INDEX "service_order_files_uploaded_by_idx" ON "service_order_files" USING btree ("uploaded_by");--> statement-breakpoint
CREATE INDEX "service_order_messages_order_visibility_idx" ON "service_order_messages" USING btree ("order_id","visibility","created_at");--> statement-breakpoint
CREATE INDEX "service_order_messages_sender_idx" ON "service_order_messages" USING btree ("sender_user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "business_settings_key_unique" ON "business_settings" USING btree ("key");--> statement-breakpoint
CREATE OR REPLACE FUNCTION "public"."prevent_append_only_mutation"()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'Table "%" is append-only; % operations are prohibited.', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'integrity_constraint_violation';
END;
$$;--> statement-breakpoint
CREATE TRIGGER "audit_logs_prevent_mutation_trg"
BEFORE UPDATE OR DELETE ON "public"."audit_logs"
FOR EACH ROW
EXECUTE FUNCTION "public"."prevent_append_only_mutation"();--> statement-breakpoint
CREATE TRIGGER "service_order_status_history_prevent_mutation_trg"
BEFORE UPDATE OR DELETE ON "public"."service_order_status_history"
FOR EACH ROW
EXECUTE FUNCTION "public"."prevent_append_only_mutation"();
