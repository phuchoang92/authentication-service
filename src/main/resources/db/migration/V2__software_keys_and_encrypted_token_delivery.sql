-- Fresh-build migration. Runtime cutover of existing data requires separate approval.
-- Key algorithms remain server-allowlisted in application policy; wider columns are not a client downgrade switch.
ALTER TABLE auth_device_key
    MODIFY public_key_spki BLOB NOT NULL,
    MODIFY algorithm VARCHAR(64) NOT NULL,
    ADD COLUMN key_format VARCHAR(24) NOT NULL DEFAULT 'SPKI_DER',
    ADD COLUMN key_version SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    ADD COLUMN thumbprint_algorithm VARCHAR(32) NOT NULL DEFAULT 'SHA-256',
    DROP CHECK ck_device_key_status,
    ADD CONSTRAINT ck_device_key_status CHECK (status IN ('ACTIVE','REVOKED','EXPIRED')),
    ADD CONSTRAINT ck_device_key_algorithm CHECK (algorithm = 'ES256'),
    ADD CONSTRAINT ck_device_key_format CHECK (key_format = 'SPKI_DER' AND key_version = 1
        AND thumbprint_algorithm = 'SHA-256');

ALTER TABLE auth_login_journey
    ADD COLUMN response_key_version SMALLINT UNSIGNED NULL,
    ADD COLUMN response_key_algorithm VARCHAR(64) NULL,
    ADD COLUMN response_key_format VARCHAR(24) NULL,
    ADD COLUMN response_key_thumbprint BINARY(32) NULL,
    ADD COLUMN response_public_jwk JSON NULL,
    ADD CONSTRAINT ck_journey_response_key CHECK (
        (response_key_version IS NULL AND response_key_algorithm IS NULL
            AND response_key_format IS NULL AND response_key_thumbprint IS NULL
            AND response_public_jwk IS NULL)
        OR (response_key_version = 1 AND response_key_algorithm = 'ECDH-ES+A256GCM'
            AND response_key_format = 'JWK' AND response_key_thumbprint IS NOT NULL
            AND response_public_jwk IS NOT NULL));

ALTER TABLE auth_result_escrow
    ADD COLUMN envelope_version SMALLINT UNSIGNED NULL,
    ADD COLUMN envelope_algorithm VARCHAR(64) NULL,
    ADD COLUMN recipient_key_thumbprint BINARY(32) NULL,
    ADD CONSTRAINT ck_escrow_envelope CHECK (
        (envelope_version IS NULL AND envelope_algorithm IS NULL
            AND recipient_key_thumbprint IS NULL)
        OR (envelope_version = 1 AND envelope_algorithm = 'ECDH-ES+A256GCM'
            AND recipient_key_thumbprint IS NOT NULL));

-- This version does not perform hardware attestation and must not mint hardware claims.
ALTER TABLE auth_device_binding
    DROP CHECK ck_binding_assurance,
    ADD CONSTRAINT ck_binding_assurance CHECK (
        possession_assurance = 'MFA_KEY_POSSESSION' AND platform_assurance = 'NONE');

ALTER TABLE auth_credential_reference
    DROP CHECK ck_credential_bio,
    ADD CONSTRAINT ck_credential_bio CHECK (biometric_enforcement = 'CLIENT_ENFORCED');
