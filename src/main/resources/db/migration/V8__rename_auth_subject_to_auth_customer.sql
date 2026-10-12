-- Preserve the applied V1-V7 checksums. MySQL updates foreign-key references on rename.
-- This migration changes only the table name; subject_id columns and named constraints remain stable.
RENAME TABLE auth_subject TO auth_customer;
