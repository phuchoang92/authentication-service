-- Auth no longer owns any authentication factor: the MFA service holds every factor and
-- challenge, and Auth stores only the MFA transaction identifier. auth_device_credential
-- (TOTP secrets, V13-V17) has no reader or writer left.
--
-- MySQL DDL is not transactional and this table holds encrypted customer factor secrets.
-- Refuse to run while any row exists; moving existing enrollments to the MFA service needs
-- a separate, approved plan.
CREATE TEMPORARY TABLE auth_v18_requires_empty_credential (
    credential_must_be_empty TINYINT NOT NULL,
    CONSTRAINT ck_v18_empty_credential CHECK (credential_must_be_empty = 0)
);

INSERT INTO auth_v18_requires_empty_credential (credential_must_be_empty)
    SELECT 1 FROM auth_device_credential LIMIT 1;

DROP TEMPORARY TABLE auth_v18_requires_empty_credential;

-- No table references auth_device_credential; its only foreign key points to
-- auth_trusted_device, which is kept.
DROP TABLE auth_device_credential;
