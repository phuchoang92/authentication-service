-- Fresh-build delta. Existing operation rows are deliberately not assigned a digest key.
-- A PASSWORD_LOGIN command must carry the server HMAC key identifier used at admission.
ALTER TABLE auth_operation
    ADD COLUMN command_digest_key_id VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL
        AFTER command_digest,
    ADD CONSTRAINT ck_operation_command_digest_key CHECK (
        (kind <> 'PASSWORD_LOGIN' OR command_digest_key_id IS NOT NULL)
        AND (command_digest_key_id IS NULL
            OR command_digest_key_id REGEXP '^[A-Za-z0-9_-]{1,16}$'));

-- A NEW_DEVICE restricted token has no trusted binding yet. A nullable binding is
-- permitted only for an issuance intent attached to its login journey.
-- The generated issuance slot also covers restricted-token issuance, so even an
-- aborted issuance retains the token-lookup uniqueness fence.
ALTER TABLE auth_authority_intent
    DROP INDEX uq_authority_lookup,
    DROP CHECK ck_authority_kind,
    MODIFY COLUMN binding_id BINARY(16) NULL,
    MODIFY COLUMN issuance_slot TINYINT GENERATED ALWAYS AS (
        CASE WHEN kind IN ('ACTIVATE','ROTATE','ISSUE_PENDING') THEN 1 ELSE NULL END
    ) STORED,
    ADD CONSTRAINT ck_authority_kind CHECK (
        kind IN ('ACTIVATE','ROTATE','ISSUE_PENDING','REVOKE','LOCK')),
    ADD CONSTRAINT ck_authority_binding CHECK (
        binding_id IS NOT NULL
        OR (kind = 'ISSUE_PENDING' AND journey_id IS NOT NULL)),
    ADD CONSTRAINT uq_authority_lookup UNIQUE
        (lookup_key_version, token_lookup_digest, issuance_slot);
