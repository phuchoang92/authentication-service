-- Phase 1 — Identity & password login.
-- Unlocks: /authentication-creation, password login, logout, initial password change.
-- Keys only: no CHECK, no FOREIGN KEY (see README "Constraint policy").

CREATE TABLE CUSTOMER_AUTHENTICATION (
    CUSTOMER_ID       VARCHAR(16)  CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    -- Mirror of the Keycloak username; compared case-insensitively on purpose.
    USER_NAME         VARCHAR(64)  COLLATE utf8mb4_0900_ai_ci NOT NULL,
    IDENTITY_ISSUER   VARCHAR(255) NOT NULL,
    IDENTITY_SUBJECT  VARCHAR(255) NOT NULL,
    STATUS            VARCHAR(16)  NOT NULL,
    VERSION           BIGINT       NOT NULL DEFAULT 0,
    CREATED_AT        DATETIME(6)  NOT NULL,
    UPDATED_AT        DATETIME(6)  NOT NULL,
    PRIMARY KEY (CUSTOMER_ID),
    UNIQUE KEY UQ_CA_USER_NAME (USER_NAME),
    UNIQUE KEY UQ_CA_IDENTITY (IDENTITY_ISSUER, IDENTITY_SUBJECT)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;

-- One OPEN request per customer and per username; READY or FAILED requests no longer block.
CREATE TABLE CUSTOMER_AUTHENTICATION_REGISTRATION (
    REQUEST_ID        BINARY(16)   NOT NULL,
    CUSTOMER_ID       VARCHAR(16)  CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    USERNAME          VARCHAR(64)  COLLATE utf8mb4_0900_ai_ci NOT NULL,
    IDENTITY_ISSUER   VARCHAR(255) NULL,
    IDENTITY_SUBJECT  VARCHAR(255) NULL,
    STATE             VARCHAR(24)  NOT NULL,
    OPEN_SLOT TINYINT GENERATED ALWAYS AS (
        CASE WHEN STATE IN ('READY', 'FAILED') THEN NULL ELSE 1 END) STORED,
    -- HMAC-SHA256 (server key) of the canonical request: a retry with other data is a conflict.
    REQUEST_DIGEST    BINARY(32)   NOT NULL,
    EXPIRES_AT        DATETIME(6)  NOT NULL,
    VERSION           BIGINT       NOT NULL DEFAULT 0,
    CREATED_AT        DATETIME(6)  NOT NULL,
    UPDATED_AT        DATETIME(6)  NOT NULL,
    PRIMARY KEY (REQUEST_ID),
    UNIQUE KEY UQ_CAR_OPEN_CUSTOMER (CUSTOMER_ID, OPEN_SLOT),
    UNIQUE KEY UQ_CAR_OPEN_USERNAME (USERNAME, OPEN_SLOT)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
