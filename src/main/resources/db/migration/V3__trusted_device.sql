-- Phase 3 — Trusted device, primary device, audit.
-- Unlocks: NEED_TRUSTED_DEVICE routing, device /list, direct primary assignment.
-- Not yet: enrollment workflow (P4), revoke (P7).

-- One row per App installation per customer and channel, current or history.
-- The installation ID is never stored in clear: HMAC for lookup, AEAD for display.
CREATE TABLE TRUSTED_DEVICE (
    ID                              BINARY(16)     NOT NULL,
    CUSTOMER_ID                     VARCHAR(16)    CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    CHANNEL                         VARCHAR(64)    CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    CLIENT_DEVICE_ID_LOOKUP         BINARY(32)     NOT NULL,
    CLIENT_DEVICE_ID_LOOKUP_KEY_ID  VARCHAR(64)    CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    CLIENT_DEVICE_ID_CIPHERTEXT     VARBINARY(512) NOT NULL,
    CLIENT_DEVICE_ID_KEY_ID         VARCHAR(64)    CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PLATFORM                        VARCHAR(16)    NOT NULL,
    STATUS                          VARCHAR(24)    NOT NULL,
    -- 1 while the row is the installation's current record; NULL for history.
    LIVE_SLOT TINYINT GENERATED ALWAYS AS (
        CASE WHEN STATUS IN ('PENDING', 'ACTIVE', 'SUSPENDED') THEN 1 ELSE NULL END) STORED,
    TRUST_LEVEL                     VARCHAR(24)    NOT NULL,
    TRUSTED_AT                      DATETIME(6)    NULL,
    EXPIRES_AT                      DATETIME(6)    NOT NULL,
    LAST_SUCCESSFUL_LOGIN_AT        DATETIME(6)    NULL,
    -- Device public key (Base64URL; sized for X-Wing: 1216 bytes = 1622 chars).
    PRIMARY_CRYPTO_SUITE            VARCHAR(96)    CHARACTER SET ascii COLLATE ascii_bin NULL,
    PRIMARY_PUBLIC_KEY              VARCHAR(2048)  CHARACTER SET ascii COLLATE ascii_bin NULL,
    PRIMARY_KEY_ID                  VARCHAR(128)   CHARACTER SET ascii COLLATE ascii_bin NULL,
    VERSION                         BIGINT         NOT NULL DEFAULT 0,
    CREATED_AT                      DATETIME(6)    NOT NULL,
    UPDATED_AT                      DATETIME(6)    NOT NULL,
    PRIMARY KEY (ID),
    -- One live row per installation; its prefix also serves the device list.
    UNIQUE KEY UQ_TD_LIVE_INSTALLATION (CUSTOMER_ID, CHANNEL, CLIENT_DEVICE_ID_LOOKUP, LIVE_SLOT)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;

-- One primary device per customer and channel: the primary key is the rule.
CREATE TABLE PRIMARY_TRUSTED_DEVICE (
    CUSTOMER_ID        VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    CHANNEL            VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY_DEVICE_ID  BINARY(16)  NULL,
    ASSIGNED_AT        DATETIME(6) NULL,
    AUTHORITY_VERSION  BIGINT      NOT NULL DEFAULT 0,
    CREATED_AT         DATETIME(6) NOT NULL,
    UPDATED_AT         DATETIME(6) NOT NULL,
    PRIMARY KEY (CUSTOMER_ID, CHANNEL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;

-- Append-only history of trust changes. One business operation writes events 0..n.
CREATE TABLE TRUSTED_DEVICE_AUDIT (
    ID                BINARY(16)   NOT NULL,
    CUSTOMER_ID       VARCHAR(16)  CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    CORRELATION_ID    VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    EVENT_SEQUENCE    INT          NOT NULL DEFAULT 0,
    EVENT_TYPE        VARCHAR(64)  NOT NULL,
    CAUSE             VARCHAR(24)  NOT NULL,
    ACTOR_TYPE        VARCHAR(24)  NOT NULL,
    ACTOR_SUBJECT     VARCHAR(255) NOT NULL,
    ACTOR_DEVICE_ID   BINARY(16)   NULL,
    ACTOR_CHANNEL     VARCHAR(64)  CHARACTER SET ascii COLLATE ascii_bin NULL,
    TARGET_DEVICE_ID  BINARY(16)   NULL,
    TARGET_CHANNEL    VARCHAR(64)  CHARACTER SET ascii COLLATE ascii_bin NULL,
    TARGET_ACTION     VARCHAR(64)  NULL,
    REASON_CODE       VARCHAR(64)  NOT NULL,
    POLICY_VERSION    VARCHAR(64)  NOT NULL,
    OCCURRED_AT       DATETIME(6)  NOT NULL,
    METADATA          JSON         NULL,
    PRIMARY KEY (ID),
    UNIQUE KEY UQ_TDA_OPERATION_SEQUENCE (CORRELATION_ID, EVENT_SEQUENCE)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
