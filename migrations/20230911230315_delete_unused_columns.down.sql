-- Add down migration script here
ALTER TABLE "users" ADD COLUMN "verified" tinyint(1) NOT NULL DEFAULT '0';
ALTER TABLE "users" ADD COLUMN "updated_at" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
