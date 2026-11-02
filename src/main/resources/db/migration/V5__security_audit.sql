-- Audit — security activity events (outside the 9 feature phases; additive only).
-- Unlocks: login history per customer. Later slices add lockout, session and enrollment activity.
--
-- Append-only and best-effort: rows are written by a background writer after the request has
-- been answered, so a row may be missing under overload. State transitions that must never be
-- lost stay in TRUSTED_DEVICE_AUDIT, which is written in the same transaction as the change.

CREATE TABLE SECURITY_AUDIT_EVENT (
    ID            BINARY(16)   NOT NULL,
    -- SecurityEventType: LOGIN_SUCCEEDED, LOGIN_FAILED, LOGIN_REFUSED, LOGIN_UNAVAILABLE.
    EVENT_TYPE    VARCHAR(40)  NOT NULL,
    -- SecurityEventReason: FULL_SESSION, RESTRICTED_SESSION, UNKNOWN_USER, WRONG_PASSWORD,
    -- LOCKED, CAPTCHA_REQUIRED, NOT_READY, REPOSITORY, PARTNER.
    REASON_CODE   VARCHAR(40)  NOT NULL,
    -- NULL when the user name is unknown. The user name itself is never stored.
    CUSTOMER_ID   VARCHAR(16)  CHARACTER SET ascii COLLATE ascii_bin NULL,
    CHANNEL       VARCHAR(64)  CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PLATFORM      VARCHAR(24)  NULL,
    -- The session a success issued; equals the correlation ID TRUSTED_DEVICE_AUDIT uses.
    SESSION_ID    BINARY(16)   NULL,
    -- Lockout count after a counted failure.
    FAILED_COUNT  INT          NULL,
    -- When the service decided (UTC) and when the writer inserted the row (UTC).
    OCCURRED_AT   DATETIME(6)  NOT NULL,
    RECORDED_AT   DATETIME(6)  NOT NULL,
    PRIMARY KEY (ID),
    KEY IX_SAE_CUSTOMER_TIME (CUSTOMER_ID, OCCURRED_AT, ID),
    KEY IX_SAE_TIME (OCCURRED_AT, ID)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
