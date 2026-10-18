package com.vpbank.dcp.core.port.out.trusteddevice;

import com.vpbank.dcp.core.domain.customer.SubjectId;

/**
 * Ksrv: a P-256 server key generated for each trust transaction. Its private half is only ever
 * stored wrapped, bound to the owner, channel and device key it was exchanged with.
 */
public interface ServerKeyExchange {

    /** Generates Ksrv and a random challenge encrypted to the device key (JWE ECDH-ES+A256GCM). */
    KeyExchangeStart begin(DeviceKeyMaterial deviceKey, SubjectId owner, String channel);

    /**
     * True only when {@code responseJwe}, encrypted to Ksrv, decrypts to exactly the stored
     * challenge. Any malformed or foreign input is false, never an exception.
     */
    boolean answers(KeyExchange exchange, SubjectId owner, String channel, String responseJwe);
}
