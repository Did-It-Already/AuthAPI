-- Add down migration script here
ALTER TABLE Persons
DROP CONSTRAINT UQ_user_id;