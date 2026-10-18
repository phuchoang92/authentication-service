-- Trusted-device continuation (draft docs/DD/target/20-trusted-device-continuation-DRAFT.md).

-- Ksrv: the server key exchanged with this binding at trust time. Auth keeps it, wrapped
-- under a versioned AES key, to verify Smart OTP for later transactions. The plaintext
-- private key is never stored.
ALTER TABLE auth_trusted_device
    ADD COLUMN server_key_id VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN server_key_ciphertext VARBINARY(1024) NULL,
    ADD CONSTRAINT ck_trusted_device_server_key CHECK
        ((server_key_id IS NULL) = (server_key_ciphertext IS NULL));

-- A binding row keeps a one-way lifecycle: the audit table allows one DEVICE_TRUSTED and
-- one DEVICE_REVOKED per row. A revoked or expired device that is trusted again therefore
-- gets a new row that carries its kept device key. Two live rows still never share a key.
ALTER TABLE auth_trusted_device
    DROP INDEX uq_trusted_device_key,
    ADD CONSTRAINT uq_trusted_device_live_key UNIQUE (device_public_key_hash, live_slot);

-- System revocations: REPLACED when a reinstalled App trusts the same device ID with a new
-- key, DEVICE_LIMIT when the oldest device is evicted to respect the configured maximum.
ALTER TABLE auth_trusted_device
    DROP CHECK ck_trusted_device_revoke_reason,
    ADD CONSTRAINT ck_trusted_device_revoke_reason CHECK (revoked_reason IS NULL OR revoked_reason IN
        ('LOST','STOLEN','CUSTOMER_REQUEST','ADMIN_ACTION','SECURITY_COMPROMISE',
         'REPLACED','DEVICE_LIMIT'));

-- A DEVICE_TRUSTED event records the MFA receipt that authorised it. This is distinct
-- from command_digest, which identifies a revocation command.
ALTER TABLE auth_security_audit_event
    ADD COLUMN mfa_receipt_digest BINARY(32) NULL,
    ADD CONSTRAINT ck_security_audit_mfa_receipt CHECK
        (mfa_receipt_digest IS NULL OR event_type = 'DEVICE_TRUSTED');
