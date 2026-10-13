-- This isolated rebuild cannot infer per-App status or safely migrate an existing
-- primary pointer. Refuse populated V10/V11 device state before any MySQL DDL.
CREATE TEMPORARY TABLE auth_v12_requires_empty_device_state (
    source_must_be_empty TINYINT NOT NULL,
    CONSTRAINT ck_v12_empty_device_state CHECK (source_must_be_empty = 0)
);
INSERT INTO auth_v12_requires_empty_device_state (source_must_be_empty)
    SELECT 1 FROM (
        SELECT auth_customer_id FROM auth_customer_app
        UNION ALL SELECT auth_customer_id FROM auth_trusted_device
        UNION ALL SELECT auth_customer_id FROM auth_biometric_login
        UNION ALL SELECT auth_customer_id FROM auth_security_audit_event
    ) existing_rows LIMIT 1;
DROP TEMPORARY TABLE auth_v12_requires_empty_device_state;

ALTER TABLE auth_security_audit_event
    DROP FOREIGN KEY fk_security_audit_customer_app;
ALTER TABLE auth_biometric_login
    DROP FOREIGN KEY fk_biometric_trusted_device;
ALTER TABLE auth_customer_app
    DROP FOREIGN KEY fk_customer_app_primary_device;
ALTER TABLE auth_trusted_device
    DROP FOREIGN KEY fk_trusted_device_customer_app;

ALTER TABLE auth_trusted_device
    RENAME COLUMN app_id TO channel,
    ADD COLUMN is_primary TINYINT NOT NULL DEFAULT 0,
    ADD COLUMN primary_slot TINYINT GENERATED ALWAYS AS
        (CASE WHEN is_primary = 1 THEN 1 ELSE NULL END) STORED,
    ADD CONSTRAINT ck_trusted_device_primary CHECK
        (is_primary IN (0, 1)
            AND (is_primary = 0 OR (status = 'ACTIVE' AND trusted_at IS NOT NULL))),
    ADD CONSTRAINT uq_trusted_device_primary UNIQUE (auth_customer_id, channel, primary_slot),
    ADD CONSTRAINT fk_trusted_device_customer FOREIGN KEY (auth_customer_id)
        REFERENCES auth_customer (id);

ALTER TABLE auth_biometric_login
    RENAME COLUMN app_id TO channel,
    ADD CONSTRAINT fk_biometric_trusted_device FOREIGN KEY
        (trusted_device_id, auth_customer_id, channel)
        REFERENCES auth_trusted_device (id, auth_customer_id, channel);

ALTER TABLE auth_security_audit_event
    RENAME COLUMN app_id TO channel,
    ADD CONSTRAINT fk_security_audit_customer FOREIGN KEY (auth_customer_id)
        REFERENCES auth_customer (id);

DROP TABLE auth_customer_app;
