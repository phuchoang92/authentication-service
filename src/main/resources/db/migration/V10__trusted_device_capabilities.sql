-- Target device schema for the isolated Authentication Service build.
-- V1-V9 and their checksums remain unchanged. Existing bindings are not copied:
-- installation_hash cannot recover the App installation ID or its AEAD ciphertext.
-- A populated V9 database requires a separately approved identity/device transition.
-- Fail instead of silently creating a second source of security authority.
CREATE TEMPORARY TABLE auth_v10_requires_empty_source (value TINYINT NOT NULL);
INSERT INTO auth_v10_requires_empty_source (value)
    SELECT NULL FROM (
        SELECT id FROM auth_customer
        UNION ALL
        SELECT id FROM auth_device_binding
    ) existing_rows LIMIT 1;
DROP TEMPORARY TABLE auth_v10_requires_empty_source;

ALTER TABLE auth_customer
    ADD COLUMN identity_provider_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN provider_subject_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD CONSTRAINT uq_customer_provider_identity UNIQUE (identity_provider_id, provider_subject_id),
    ADD CONSTRAINT ck_customer_provider_identity CHECK (
        (identity_provider_id IS NULL AND provider_subject_id IS NULL)
        OR (identity_provider_id IS NOT NULL AND provider_subject_id IS NOT NULL));

CREATE TABLE auth_customer_app (
    auth_customer_id BINARY(16) NOT NULL,
    app_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    primary_trusted_device_id BINARY(16) NULL,
    status VARCHAR(16) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (auth_customer_id, app_id),
    CONSTRAINT fk_customer_app_customer FOREIGN KEY (auth_customer_id) REFERENCES auth_customer (id),
    CONSTRAINT ck_customer_app_status CHECK (status IN ('ACTIVE','BLOCKED')),
    CONSTRAINT ck_customer_app_version CHECK (version BETWEEN 0 AND 9007199254740991)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;

CREATE TABLE auth_trusted_device (
    id BINARY(16) NOT NULL,
    auth_customer_id BINARY(16) NOT NULL,
    app_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    device_id_lookup BINARY(32) NOT NULL,
    device_id_lookup_key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    -- Public installationId permits 300 UTF-8 characters; AEAD adds nonce/tag/version.
    device_id_ciphertext VARBINARY(2048) NOT NULL,
    device_id_key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    platform VARCHAR(16) NOT NULL,
    os_version VARCHAR(64) NULL,
    os_build VARCHAR(64) NULL,
    app_version_name VARCHAR(64) NULL,
    app_build VARCHAR(64) NULL,
    app_metadata_reported_at DATETIME(6) NULL,
    label VARCHAR(100) NOT NULL,
    manufacturer VARCHAR(100) NULL,
    model VARCHAR(100) NULL,
    status VARCHAR(24) NOT NULL,
    live_slot TINYINT GENERATED ALWAYS AS
        (CASE WHEN status IN ('PENDING_RESET','ACTIVE') THEN 1 ELSE NULL END) STORED,
    device_public_key VARBINARY(2048) NOT NULL,
    device_public_key_hash BINARY(32) NOT NULL,
    device_key_algorithm VARCHAR(32) NOT NULL,
    device_security_version BIGINT NOT NULL DEFAULT 0,
    trust_method VARCHAR(40) NOT NULL,
    trust_policy_version VARCHAR(64) NOT NULL,
    possession_assurance VARCHAR(32) NOT NULL,
    trusted_at DATETIME(6) NULL,
    expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    revoked_reason VARCHAR(24) NULL,
    revoked_by_type VARCHAR(16) NULL,
    revoked_by_id VARCHAR(128) NULL,
    last_authenticated_at DATETIME(6) NULL,
    version BIGINT NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uq_trusted_device_owner UNIQUE (id, auth_customer_id, app_id),
    CONSTRAINT uq_trusted_device_key UNIQUE (device_public_key_hash),
    CONSTRAINT uq_trusted_device_live_installation UNIQUE
        (auth_customer_id, app_id, device_id_lookup, live_slot),
    CONSTRAINT fk_trusted_device_customer_app FOREIGN KEY (auth_customer_id, app_id)
        REFERENCES auth_customer_app (auth_customer_id, app_id),
    CONSTRAINT ck_trusted_device_platform CHECK (platform IN ('ANDROID','IOS')),
    CONSTRAINT ck_trusted_device_status CHECK (status IN ('PENDING_RESET','ACTIVE','REVOKED','EXPIRED')),
    CONSTRAINT ck_trusted_device_key_algorithm CHECK (device_key_algorithm = 'ES256'),
    CONSTRAINT ck_trusted_device_assurance CHECK (possession_assurance = 'MFA_KEY_POSSESSION'),
    CONSTRAINT ck_trusted_device_version CHECK (version BETWEEN 0 AND 9007199254740991),
    CONSTRAINT ck_trusted_device_security_version CHECK
        (device_security_version BETWEEN 0 AND 9007199254740991),
    CONSTRAINT ck_trusted_device_revocation CHECK (
        (status = 'REVOKED' AND revoked_at IS NOT NULL AND revoked_reason IS NOT NULL
            AND revoked_by_type IS NOT NULL AND revoked_by_id IS NOT NULL)
        OR (status <> 'REVOKED' AND revoked_at IS NULL AND revoked_reason IS NULL
            AND revoked_by_type IS NULL AND revoked_by_id IS NULL)),
    CONSTRAINT ck_trusted_device_revoke_reason CHECK (revoked_reason IS NULL OR revoked_reason IN
        ('LOST','STOLEN','CUSTOMER_REQUEST','ADMIN_ACTION','SECURITY_COMPROMISE')),
    CONSTRAINT ck_trusted_device_revoke_actor CHECK (revoked_by_type IS NULL OR revoked_by_type IN
        ('CUSTOMER','ADMIN','SYSTEM')),
    INDEX ix_trusted_device_list (auth_customer_id, app_id, status, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;

ALTER TABLE auth_customer_app
    ADD CONSTRAINT fk_customer_app_primary_device
        FOREIGN KEY (primary_trusted_device_id, auth_customer_id, app_id)
        REFERENCES auth_trusted_device (id, auth_customer_id, app_id);

CREATE TABLE auth_device_push_registration (
    id BINARY(16) NOT NULL,
    trusted_device_id BINARY(16) NOT NULL,
    provider VARCHAR(16) NOT NULL,
    environment VARCHAR(16) NOT NULL,
    token_ciphertext VARBINARY(4096) NOT NULL,
    token_key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(16) NOT NULL,
    refreshed_at DATETIME(6) NOT NULL,
    invalidated_at DATETIME(6) NULL,
    version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT uq_push_registration_current UNIQUE (trusted_device_id, provider, environment),
    CONSTRAINT fk_push_registration_device FOREIGN KEY (trusted_device_id)
        REFERENCES auth_trusted_device (id),
    CONSTRAINT ck_push_registration_provider CHECK (provider IN ('FCM','APNS')),
    CONSTRAINT ck_push_registration_environment CHECK (environment IN ('PRODUCTION','SANDBOX')),
    CONSTRAINT ck_push_registration_status CHECK
        ((status = 'ACTIVE' AND invalidated_at IS NULL)
          OR (status = 'INVALID' AND invalidated_at IS NOT NULL)),
    CONSTRAINT ck_push_registration_version CHECK (version BETWEEN 0 AND 9007199254740991)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;

CREATE TABLE auth_biometric_login (
    id BINARY(16) NOT NULL,
    trusted_device_id BINARY(16) NOT NULL,
    auth_customer_id BINARY(16) NOT NULL,
    app_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    credential_provider_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    provider_credential_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    provider_credential_version BIGINT NOT NULL,
    status VARCHAR(24) NOT NULL,
    current_slot TINYINT GENERATED ALWAYS AS
        (CASE WHEN status IN ('ACTIVE','SUSPENDED') THEN 1 ELSE NULL END) STORED,
    biometric_enforcement VARCHAR(32) NOT NULL,
    registered_at DATETIME(6) NOT NULL,
    suspended_at DATETIME(6) NULL,
    revoked_at DATETIME(6) NULL,
    version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT uq_biometric_provider_credential UNIQUE
        (credential_provider_id, provider_credential_id),
    CONSTRAINT uq_biometric_current_binding UNIQUE (trusted_device_id, current_slot),
    CONSTRAINT fk_biometric_trusted_device FOREIGN KEY
        (trusted_device_id, auth_customer_id, app_id)
        REFERENCES auth_trusted_device (id, auth_customer_id, app_id),
    CONSTRAINT ck_biometric_status CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED')),
    CONSTRAINT ck_biometric_enforcement CHECK (biometric_enforcement = 'CLIENT_ENFORCED'),
    CONSTRAINT ck_biometric_timestamps CHECK (
        (status = 'ACTIVE' AND suspended_at IS NULL AND revoked_at IS NULL)
        OR (status = 'SUSPENDED' AND suspended_at IS NOT NULL AND revoked_at IS NULL)
        OR (status = 'REVOKED' AND revoked_at IS NOT NULL)),
    CONSTRAINT ck_biometric_version CHECK (version BETWEEN 0 AND 9007199254740991),
    CONSTRAINT ck_biometric_provider_version CHECK
        (provider_credential_version BETWEEN 0 AND 9007199254740991),
    INDEX ix_biometric_owner (auth_customer_id, app_id, status, trusted_device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;

CREATE TABLE auth_security_audit_event (
    id BINARY(16) NOT NULL,
    auth_customer_id BINARY(16) NOT NULL,
    app_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    operation_id BINARY(16) NOT NULL,
    event_sequence INT NOT NULL,
    event_type VARCHAR(40) NOT NULL,
    trusted_device_id BINARY(16) NULL,
    previous_primary_device_id BINARY(16) NULL,
    new_primary_device_id BINARY(16) NULL,
    device_security_version BIGINT NULL,
    reason_code VARCHAR(40) NULL,
    actor_type VARCHAR(16) NOT NULL,
    actor_id VARCHAR(128) NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    recorded_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uq_security_audit_operation_sequence UNIQUE (operation_id, event_sequence),
    CONSTRAINT uq_security_audit_device_transition UNIQUE (event_type, trusted_device_id),
    CONSTRAINT fk_security_audit_customer_app FOREIGN KEY (auth_customer_id, app_id)
        REFERENCES auth_customer_app (auth_customer_id, app_id),
    CONSTRAINT ck_security_audit_sequence CHECK (event_sequence >= 0),
    CONSTRAINT ck_security_audit_actor CHECK (actor_type IN ('CUSTOMER','ADMIN','SYSTEM')),
    CONSTRAINT ck_security_audit_shape CHECK (
        (event_type IN ('DEVICE_TRUSTED','DEVICE_REVOKED')
            AND trusted_device_id IS NOT NULL AND device_security_version IS NOT NULL
            AND previous_primary_device_id IS NULL AND new_primary_device_id IS NULL
            AND (event_type <> 'DEVICE_REVOKED' OR reason_code IS NOT NULL))
        OR (event_type = 'PRIMARY_DEVICE_CHANGED'
            AND trusted_device_id IS NULL AND device_security_version IS NULL
            AND NOT (previous_primary_device_id <=> new_primary_device_id))),
    INDEX ix_security_audit_owner_time (auth_customer_id, app_id, occurred_at, id),
    INDEX ix_security_audit_device_time (trusted_device_id, occurred_at, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
