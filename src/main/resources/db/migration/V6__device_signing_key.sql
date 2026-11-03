-- Slice 13 — the device proves its signing key at login.
-- The device key becomes an ML-DSA-65 JWK ({"alg":"ML-DSA-65","kty":"AKP","pub":<1952 bytes base64url>}),
-- about 2.7 KB of canonical text; the column grows to hold it. Existing P-256 rows are unchanged data.
ALTER TABLE TRUSTED_DEVICE
    MODIFY PRIMARY_PUBLIC_KEY VARCHAR(4096) CHARACTER SET ascii COLLATE ascii_bin NULL;
