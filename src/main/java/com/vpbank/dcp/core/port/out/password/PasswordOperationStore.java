package com.vpbank.dcp.core.port.out.password;

import java.util.UUID;

/** Durable one-dispatch reservation; implementation owns its short SQL transactions. */
public interface PasswordOperationStore {

    PasswordReservationResult reserve(PasswordReservation reservation);

    PasswordDispatchResult claimDispatch(UUID operationId);

    /** Records a definite Keycloak rejection. A concurrent cancellation wins. */
    PasswordCredentialRecordResult recordRejection(UUID operationId);

    /** Records an unknown dispatch outcome without authorizing another password call. */
    PasswordCredentialRecordResult recordUncertain(UUID operationId);
}
