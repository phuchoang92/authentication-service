-- The retired Authority Control capability has no application/session consumers.
-- Preserve applied V1-V8 checksums; remove its unused controller state additively.
DROP TABLE auth_authority_control;
