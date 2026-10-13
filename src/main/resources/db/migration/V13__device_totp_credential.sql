-- Auth owns the TOTP verifier. A credential belongs to one trusted binding; it
-- does not grant trust, login, or transaction approval by itself.
CREATE TABLE auth_device_totp_credential (
    id BINARY(16) NOT NULL,
    trusted_device_id BINARY(16) NOT NULL,
    secret_ciphertext VARBINARY(256) NOT NULL,
    secret_key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status VARCHAR(16) NOT NULL,
    current_slot TINYINT GENERATED ALWAYS AS
        (CASE WHEN status = 'ACTIVE' THEN 1 ELSE NULL END) STORED,
    last_accepted_step BIGINT NOT NULL DEFAULT -1,
    version BIGINT NOT NULL DEFAULT 0,
    activated_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_device_totp_trusted_device FOREIGN KEY (trusted_device_id)
        REFERENCES auth_trusted_device (id),
    CONSTRAINT uq_device_totp_current UNIQUE (trusted_device_id, current_slot),
    CONSTRAINT ck_device_totp_status CHECK
        ((status = 'ACTIVE' AND revoked_at IS NULL)
          OR (status = 'REVOKED' AND revoked_at IS NOT NULL)),
    CONSTRAINT ck_device_totp_step CHECK (last_accepted_step >= -1),
    CONSTRAINT ck_device_totp_version CHECK (version BETWEEN 0 AND 9007199254740991),
    INDEX ix_device_totp_binding (trusted_device_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
