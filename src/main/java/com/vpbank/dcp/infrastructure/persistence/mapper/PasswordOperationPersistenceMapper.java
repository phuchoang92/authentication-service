package com.vpbank.dcp.infrastructure.persistence.mapper;

import com.vpbank.dcp.core.domain.customer.VerifiedProviderIdentity;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.password.ConfirmedPasswordOwner;
import com.vpbank.dcp.core.port.out.password.PasswordOperationProgress;
import com.vpbank.dcp.core.port.out.password.PasswordReservationResult;
import com.vpbank.dcp.infrastructure.persistence.projection.ConfirmedPasswordOwnerView;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordOperationProgressView;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordReservationView;
import com.vpbank.dcp.infrastructure.persistence.projection.VerifiedPasswordIdentityView;

/** Converts operation projections into core-owned values; no workflow decisions. */
public final class PasswordOperationPersistenceMapper {
    private PasswordOperationPersistenceMapper() { }

    public static PasswordOperationProgress toProgress(PasswordOperationProgressView view) {
        return PasswordOperationProgress.valueOf(view.state());
    }

    public static VerifiedProviderIdentity toVerifiedIdentity(VerifiedPasswordIdentityView view) {
        return new VerifiedProviderIdentity(view.issuer(), view.subject());
    }

    public static ConfirmedPasswordOwner toConfirmedOwner(ConfirmedPasswordOwnerView view) {
        return new ConfirmedPasswordOwner(new VerifiedProviderIdentity(view.issuer(), view.providerSubject()),
                CustomerOwnerPersistenceMapper.toDomain(view.customer()), view.customer().id());
    }

    public static PasswordReservationResult.Existing toExistingReservation(PasswordReservationView view) {
        return new PasswordReservationResult.Existing(view.operationId(), view.journeyId(),
                Digest32.fromBytes(view.commandDigest()), view.commandKeyId());
    }
}
