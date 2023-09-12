-- Add up migration script here
ALTER TABLE "users" DROP COLUMN "verified";
ALTER TABLE "users" DROP COLUMN "updated_at";