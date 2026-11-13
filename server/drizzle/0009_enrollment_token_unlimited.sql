-- Enrollment tokens without expiry (expires_at NULL = never expires)
ALTER TABLE "enrollment_tokens" ALTER COLUMN "expires_at" DROP NOT NULL;
