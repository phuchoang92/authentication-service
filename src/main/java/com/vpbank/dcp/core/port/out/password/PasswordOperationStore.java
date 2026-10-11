package com.vpbank.dcp.core.port.out.password;

import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRoute;
import java.util.Optional;
import java.util.UUID;

/** Durable one-dispatch reservation; implementation owns its short SQL transactions. */
public interface PasswordOperationStore {

    PasswordReservationResult reserve(PasswordReservation reservation);

    PasswordDispatchResult claimDispatch(UUID operationId);

    /** Reads the committed outcome; never dispatches credentials or restores authority. */
    PasswordOperationProgress progress(UUID operationId);

    /** Persist verified issuer/sub before any Customer call; a lost write never authorizes redispatch. */
    PasswordCredentialRecordResult recordVerifiedIdentity(
            UUID operationId, VerifiedProviderIdentity identity);

    /** Only an already durable identity may be used to resume Customer resolution. */
    Optional<VerifiedProviderIdentity> verifiedIdentity(UUID operationId);

    /** Reads the original committed Customer owner; activation must still check live guards. */
    Optional<ConfirmedPasswordOwner> confirmedOwner(UUID operationId);

    /** Freezes a route that cannot proceed until real MFA exists; never issues a token. */
    PasswordCredentialRecordResult recordMfaUnavailable(UUID operationId, TrustedDeviceRoute route);

    /** Records a definite Keycloak rejection. A concurrent cancellation wins. */
    PasswordCredentialRecordResult recordRejection(UUID operationId);

    /** Records an unknown dispatch outcome without authorizing another password call. */
    PasswordCredentialRecordResult recordUncertain(UUID operationId);
}
