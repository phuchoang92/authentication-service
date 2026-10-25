package com.vpbank.dcp.auth.application.port.out;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;

/**
 * Wraps the token for the app: compact JWE ECDH-ES/A256GCM to the app's public P-256 key (DD 06).
 * Throws {@link InvalidEncryptionKeyException} when the key is unusable.
 */
public interface TokenEnvelopeSealer {
    String seal(String recipientPublicJwk, OpaqueToken token, Session session);
}
