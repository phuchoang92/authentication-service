-- Phase 4 — Enrollment & approval (two MFA phases).
-- Unlocks: /enrollment/*, /primary/enrollment/*, /authorize, /pending, MFA /callback.

CREATE TABLE TRUSTED_DEVICE_ENROLLMENT (
    ID                                  BINARY(16)   NOT NULL,
    CUSTOMER_ID                         VARCHAR(16)  CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    CHANNEL                             VARCHAR(64)  CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PURPOSE                             VARCHAR(32)  NOT NULL,
    STATE                               VARCHAR(32)  NOT NULL,
    REQUESTER_DEVICE_ID                 BINARY(16)   NULL,
    ACTOR_DEVICE_ID                     BINARY(16)   NULL,
    TARGET_DEVICE_ID                    BINARY(16)   NULL,
    -- Installation IDs of devices that have no row yet: HMAC lookup only.
    REQUESTER_CLIENT_DEVICE_ID_LOOKUP   BINARY(32)   NULL,
    TARGET_CLIENT_DEVICE_ID_LOOKUP      BINARY(32)   NULL,
    CLIENT_DEVICE_ID_LOOKUP_KEY_ID      VARCHAR(64)  CHARACTER SET ascii COLLATE ascii_bin NULL,
    -- First MFA: the step that starts the enrollment.
    MULTIFACTOR_ID                      VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    CONFIRMED_MFA_METHOD                VARCHAR(64)  NULL,
    MFA_CONFIRMED_AT                    DATETIME(6)  NULL,
    -- Second MFA: the authorization the approving device gives.
    AUTHORIZATION_TOKEN_DIGEST          BINARY(32)   NULL,
    AUTHORIZATION_EXPIRES_AT            DATETIME(6)  NULL,
    AUTHORIZATION_ATTEMPTS              INT          NOT NULL DEFAULT 0,
    AUTHORIZATION_CONSUMED_AT           DATETIME(6)  NULL,
    AUTHORIZATION_MULTIFACTOR_ID        VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    AUTHORIZATION_MFA_METHOD            VARCHAR(64)  NULL,
    AUTHORIZATION_MFA_CONFIRMED_AT      DATETIME(6)  NULL,
    AUTHORIZED_SESSION_REF_DIGEST       BINARY(32)   NULL,
    AUTHORIZATION_CLAIM_SESSION_DIGEST  BINARY(32)   NULL,
    EXPIRES_AT                          DATETIME(6)  NOT NULL,
    CREATION_IDEMPOTENCY_DIGEST         BINARY(32)   NOT NULL,
    VERSION                             BIGINT       NOT NULL DEFAULT 0,
    CREATED_AT                          DATETIME(6)  NOT NULL,
    UPDATED_AT                          DATETIME(6)  NOT NULL,
    PRIMARY KEY (ID),
    -- A retried create returns the same enrollment; the prefix serves "open enrollments".
    UNIQUE KEY UQ_DE_CREATION (CUSTOMER_ID, CHANNEL, PURPOSE, CREATION_IDEMPOTENCY_DIGEST)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;

ALTER TABLE PRIMARY_TRUSTED_DEVICE
    ADD COLUMN PRIMARY_ENROLLMENT_ID  BINARY(16)  NULL,
    ADD COLUMN FACE_AUTHENTICATED     TINYINT(1)  NOT NULL DEFAULT 0,
    ADD COLUMN PRIMARY_MODE           VARCHAR(24) NULL;

ALTER TABLE TRUSTED_DEVICE_AUDIT
    ADD COLUMN ENROLLMENT_ID BINARY(16) NULL;
