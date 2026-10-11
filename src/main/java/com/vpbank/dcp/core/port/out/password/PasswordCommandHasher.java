package com.vpbank.dcp.core.port.out.password;

import com.vpbank.dcp.core.domain.security.Digest32;

/** Server-keyed fingerprint for stable idempotency; never expose its key to App/BFF. */
public interface PasswordCommandHasher {

    String activeKeyId();

    Digest32 digest(PasswordSemanticCommand command, String keyId);

    PasswordReservationFingerprints prepare(PasswordSemanticCommand command);
}
