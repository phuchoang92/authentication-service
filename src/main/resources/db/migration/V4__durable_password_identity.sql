ALTER TABLE auth_operation
    ADD COLUMN verified_issuer VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN verified_subject VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN verified_at DATETIME(6) NULL;

ALTER TABLE auth_operation
    DROP CHECK ck_operation_state;

ALTER TABLE auth_operation
    ADD CONSTRAINT ck_operation_state
        CHECK (state IN ('RESERVED','DISPATCHED','VERIFIED','UNCERTAIN',
                        'CONFIRMED','REJECTED','COMPLETED')),
    ADD CONSTRAINT ck_operation_verified_identity
        CHECK ((verified_issuer IS NULL AND verified_subject IS NULL AND verified_at IS NULL
                AND state NOT IN ('VERIFIED','CONFIRMED','COMPLETED'))
               OR (verified_issuer IS NOT NULL AND verified_subject IS NOT NULL
                   AND verified_at IS NOT NULL));
