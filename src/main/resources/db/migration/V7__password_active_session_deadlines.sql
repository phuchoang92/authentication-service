-- Keep the exact issued deadlines durable for same-envelope recovery. This is not serving authority.
ALTER TABLE auth_authority_intent
    ADD COLUMN idle_expires_at DATETIME(6) NULL,
    ADD COLUMN absolute_expires_at DATETIME(6) NULL,
    ADD CONSTRAINT ck_authority_password_deadlines CHECK (
        kind <> 'ACTIVATE' OR
        (idle_expires_at IS NOT NULL AND absolute_expires_at IS NOT NULL
         AND idle_expires_at <= absolute_expires_at AND absolute_expires_at = deadline));
