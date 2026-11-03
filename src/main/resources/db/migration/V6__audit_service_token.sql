-- Audit — service-token events on SECURITY_AUDIT_EVENT (slice 12, 2026-11-03; additive only).
-- Unlocks: which internal service obtained (or was refused) a scoped token, when, for which scope.
--
-- A service-token event has no customer, channel, platform or session: CHANNEL becomes nullable and
-- three columns name the service, the scope and the token. The application decides which columns an
-- event must carry (login events still carry CHANNEL); the table only allows both shapes.

ALTER TABLE SECURITY_AUDIT_EVENT
    -- NULL for service-token events (SERVICE_TOKEN_ISSUED / SERVICE_TOKEN_REFUSED); set for every login event.
    MODIFY CHANNEL    VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    -- ServiceId of the calling service, as its client assertion named it.
    ADD COLUMN SERVICE_ID VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER FAILED_COUNT,
    -- ServiceScope wire code (onboarding).
    ADD COLUMN SCOPE      VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER SERVICE_ID,
    -- The issued token's jti; NULL when refused. The token itself is never stored.
    ADD COLUMN TOKEN_ID   BINARY(16)  NULL AFTER SCOPE,
    ADD KEY IX_SAE_SERVICE_TIME (SERVICE_ID, OCCURRED_AT, ID);
