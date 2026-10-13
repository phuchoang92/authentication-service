-- An enrollment occupies the same one-current-credential slot as an ACTIVE TOTP
-- credential. The first accepted code changes PENDING to ACTIVE under the row lock.
ALTER TABLE auth_device_credential
    DROP CHECK ck_device_totp_status,
    DROP INDEX uq_device_totp_current,
    MODIFY COLUMN activated_at DATETIME(6) NULL,
    ADD COLUMN public_credential_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN public_enrollment_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN enrollment_expires_at DATETIME(6) NULL,
    ADD COLUMN recipient_public_jwk VARCHAR(2048) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD CONSTRAINT uq_device_credential_public_id UNIQUE (public_credential_id),
    ADD CONSTRAINT uq_device_enrollment_public_id UNIQUE (public_enrollment_id),
    ADD CONSTRAINT ck_device_credential_lifecycle CHECK (
        (status = 'PENDING' AND activated_at IS NULL AND revoked_at IS NULL
            AND enrollment_expires_at IS NOT NULL AND recipient_public_jwk IS NOT NULL
            AND public_enrollment_id IS NOT NULL)
        OR (status = 'ACTIVE' AND activated_at IS NOT NULL AND revoked_at IS NULL
            AND enrollment_expires_at IS NULL AND recipient_public_jwk IS NULL)
        OR (status = 'REVOKED' AND revoked_at IS NOT NULL)),
    ADD CONSTRAINT ck_device_credential_public_id CHECK
        (public_credential_id IS NULL OR CHAR_LENGTH(public_credential_id) BETWEEN 22 AND 64),
    ADD CONSTRAINT ck_device_enrollment_public_id CHECK
        (public_enrollment_id IS NULL OR CHAR_LENGTH(public_enrollment_id) BETWEEN 22 AND 64);

ALTER TABLE auth_device_credential
    MODIFY COLUMN current_slot TINYINT GENERATED ALWAYS AS
        (CASE WHEN status IN ('PENDING','ACTIVE') THEN 1 ELSE NULL END) STORED,
    ADD CONSTRAINT uq_device_credential_current UNIQUE (trusted_device_id, current_slot);

-- Only the cross-service trust/reset operation needs durable progress. Password
-- dispatch and short-lived MFA challenges are deliberately not stored here.
CREATE TABLE auth_device_trust_reset (
    id BINARY(16) NOT NULL,
    public_result_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    auth_customer_id BINARY(16) NOT NULL,
    trusted_device_id BINARY(16) NOT NULL,
    reset_operation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    state VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    mfa_receipt_digest BINARY(32) NOT NULL,
    enrollment_proof_digest BINARY(32) NOT NULL,
    target_credential_security_version BIGINT NOT NULL,
    reset_ack_jws TEXT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT uq_device_trust_result UNIQUE (public_result_id),
    CONSTRAINT uq_device_trust_binding UNIQUE (trusted_device_id),
    CONSTRAINT uq_device_trust_reset_operation UNIQUE (reset_operation_id),
    CONSTRAINT fk_device_trust_customer FOREIGN KEY (auth_customer_id)
        REFERENCES auth_customer (id),
    CONSTRAINT fk_device_trust_binding FOREIGN KEY (trusted_device_id)
        REFERENCES auth_trusted_device (id),
    CONSTRAINT ck_device_trust_reset_state CHECK
        (state IN ('PENDING_RESET','RESET_DISPATCHED','RESET_CONFIRMED','ACTIVE','FAILED')),
    CONSTRAINT ck_device_trust_reset_version CHECK
        (version BETWEEN 0 AND 9007199254740991),
    CONSTRAINT ck_device_trust_target_version CHECK
        (target_credential_security_version BETWEEN 0 AND 9007199254740991),
    CONSTRAINT ck_device_trust_reset_ack CHECK
        ((state IN ('RESET_CONFIRMED','ACTIVE') AND reset_ack_jws IS NOT NULL)
          OR (state IN ('PENDING_RESET','RESET_DISPATCHED','FAILED') AND reset_ack_jws IS NULL)),
    INDEX ix_device_trust_work (state, updated_at, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
