ALTER TABLE auth_operation
    DROP CHECK ck_operation_state;

ALTER TABLE auth_operation
    ADD CONSTRAINT ck_operation_state
        CHECK (state IN ('RESERVED','DISPATCHED','VERIFIED','UNCERTAIN',
                        'CONFIRMED','MFA_UNAVAILABLE','REJECTED','COMPLETED'));

ALTER TABLE auth_operation
    DROP CHECK ck_operation_verified_identity;

ALTER TABLE auth_operation
    ADD CONSTRAINT ck_operation_verified_identity
        CHECK ((verified_issuer IS NULL AND verified_subject IS NULL AND verified_at IS NULL
                AND state NOT IN ('VERIFIED','CONFIRMED','MFA_UNAVAILABLE','COMPLETED'))
               OR (verified_issuer IS NOT NULL AND verified_subject IS NOT NULL
                   AND verified_at IS NOT NULL));
