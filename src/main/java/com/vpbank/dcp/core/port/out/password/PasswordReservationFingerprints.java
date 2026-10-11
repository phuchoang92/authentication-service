package com.vpbank.dcp.core.port.out.password;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.util.Objects;

/** Stable, non-secret digests stored before the one allowed KC dispatch. */
public record PasswordReservationFingerprints(Digest32 ownerScope,
                                              Digest32 idempotency,
                                              Digest32 command,
                                              String commandKeyId,
                                              Digest32 installation) {

    public PasswordReservationFingerprints {
        Objects.requireNonNull(ownerScope, "ownerScope");
        Objects.requireNonNull(idempotency, "idempotency");
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(commandKeyId, "commandKeyId");
        Objects.requireNonNull(installation, "installation");
        if (!commandKeyId.matches("[A-Za-z0-9_-]{1,16}")) {
            throw new InvalidPasswordOperationException();
        }
    }
}
