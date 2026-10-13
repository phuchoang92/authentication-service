-- Credential-wide budget prevents a caller from gaining more guesses by starting
-- another login or transfer request. Limits come from validated runtime policy.
ALTER TABLE auth_device_totp_credential
    ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN blocked_until DATETIME(6) NULL,
    ADD CONSTRAINT ck_device_totp_failed_attempts CHECK (failed_attempts BETWEEN 0 AND 100);
