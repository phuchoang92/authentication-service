-- Trusted-device key exchange moves to HPKE X-Wing (draft-connolly-cfrg-xwing-kem-11, suite
-- DCP-HPKE-XWING-SHA256-AES256GCM-V1). A new trusted device stores its raw 1216-byte X-Wing public
-- key and device_public_key_hash = SHA-256 of those bytes. Rows already written as ES256 stay
-- valid data; they can no longer complete a key exchange and need a new trust.
ALTER TABLE auth_trusted_device
    DROP CHECK ck_trusted_device_key_algorithm,
    ADD CONSTRAINT ck_trusted_device_key_algorithm CHECK
        (device_key_algorithm = 'ES256'
            OR (device_key_algorithm = 'XWING-MLKEM768-X25519'
                AND LENGTH(device_public_key) = 1216));

-- Ksrv is stored wrapped by a KEK: 0x03 ‖ nonce ‖ AES-256-GCM(JDK ML-KEM and X25519 PKCS#8 keys with
-- the public key) ‖ tag, about 3.7 KB. JDK 25 cannot hold ML-KEM keys as a seed, hence the size.
ALTER TABLE auth_trusted_device
    MODIFY server_key_ciphertext VARBINARY(4096) NULL;
