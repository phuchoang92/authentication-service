package com.vpbank.dcp.core.trusteddevice;

import com.vpbank.dcp.core.session.KeyExchange;
import com.vpbank.dcp.core.customer.SubjectId;

/**
 * Ksrv: a server key generated for each trust transaction. Its private half is only ever stored
 * wrapped, bound to the owner, channel and device key it was exchanged with.
 */
public interface ServerKeyExchange {

    /**
     * Generates Ksrv, an enrollment ID and a random challenge encrypted to the device key, bound to
     * that enrollment ID.
     */
    KeyExchangeStart begin(DeviceKeyMaterial deviceKey, SubjectId owner, String channel);

    /**
     * True only when {@code keyExchangeProof}, encrypted to Ksrv for this enrollment ID, decrypts
     * to exactly the stored challenge. Any malformed or foreign input is false, never an exception.
     */
    boolean answers(KeyExchange exchange, SubjectId owner, String channel, String keyExchangeProof);
}
