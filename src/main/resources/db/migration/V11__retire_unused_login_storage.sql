-- Retire the V1 password journey/operation model in the isolated rebuild.
-- MySQL DDL is not transactional. Reject any populated old table before the
-- first DROP; migration of existing login/device data needs a separate plan.
CREATE TEMPORARY TABLE auth_v11_requires_empty_source (
    source_must_be_empty TINYINT NOT NULL,
    CONSTRAINT ck_v11_empty_source CHECK (source_must_be_empty = 0)
);

INSERT INTO auth_v11_requires_empty_source (source_must_be_empty)
    SELECT 1 FROM (
        SELECT id FROM auth_identity_link
        UNION ALL SELECT subject_id FROM auth_subject_app
        UNION ALL SELECT id FROM auth_device_binding
        UNION ALL SELECT id FROM auth_device_key
        UNION ALL SELECT id FROM auth_login_journey
        UNION ALL SELECT id FROM auth_operation
        UNION ALL SELECT id FROM auth_device_enrollment
        UNION ALL SELECT id FROM auth_platform_app_key
        UNION ALL SELECT id FROM auth_attestation_assessment
        UNION ALL SELECT id FROM auth_credential_reference
        UNION ALL SELECT id FROM auth_mfa_step
        UNION ALL SELECT id FROM auth_mfa_challenge
        UNION ALL SELECT id FROM auth_mfa_attempt
        UNION ALL SELECT id FROM auth_security_operation
        UNION ALL SELECT id FROM auth_security_guard
        UNION ALL SELECT id FROM auth_authority_intent
        UNION ALL SELECT operation_id FROM auth_result_escrow
        UNION ALL SELECT id FROM auth_outbox
        UNION ALL SELECT id FROM auth_customer_event_inbox
    ) existing_rows LIMIT 1;

DROP TEMPORARY TABLE auth_v11_requires_empty_source;

-- The old App row points back to its last binding. Remove this FK first,
-- then drop child tables before their parents. The new customer/App/device
-- tables created in V10 are not touched.
ALTER TABLE auth_subject_app DROP FOREIGN KEY fk_subject_app_last_binding;

DROP TABLE auth_customer_event_inbox;
DROP TABLE auth_outbox;
DROP TABLE auth_result_escrow;
DROP TABLE auth_authority_intent;
DROP TABLE auth_security_guard;
DROP TABLE auth_security_operation;
DROP TABLE auth_mfa_attempt;
DROP TABLE auth_mfa_challenge;
DROP TABLE auth_mfa_step;
DROP TABLE auth_attestation_assessment;
DROP TABLE auth_credential_reference;
DROP TABLE auth_platform_app_key;
DROP TABLE auth_device_enrollment;
DROP TABLE auth_operation;
DROP TABLE auth_login_journey;
DROP TABLE auth_device_key;
DROP TABLE auth_device_binding;
DROP TABLE auth_identity_link;
DROP TABLE auth_subject_app;
