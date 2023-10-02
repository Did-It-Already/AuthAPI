-- Add up migration script here
ALTER TABLE users
ADD CONSTRAINT UQ_user_id UNIQUE(user_id);