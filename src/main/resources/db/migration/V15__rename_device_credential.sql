-- Rename the Auth-owned device credential table without recreating credentials.
-- The credential ID remains an internal BINARY(16) key; external IDs are opaque contracts.
RENAME TABLE auth_device_totp_credential TO auth_device_credential;
