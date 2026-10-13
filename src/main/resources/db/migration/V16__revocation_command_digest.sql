-- Earlier revoke events cannot be reconstructed into their original commands.
-- New events carry a digest; a retry of an earlier event without one fails closed.
ALTER TABLE auth_security_audit_event
    ADD COLUMN command_digest BINARY(32) NULL;
