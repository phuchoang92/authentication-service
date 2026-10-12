package com.vpbank.dcp.infrastructure.persistence.mapper;

import com.vpbank.dcp.core.domain.device.DeviceCandidate;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceRouteEvidence;
import com.vpbank.dcp.infrastructure.persistence.projection.DeviceCandidateView;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordDeviceRouteView;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Optional;

/** Restores route evidence; the core routing policy still selects the route. */
public final class PasswordDeviceRoutePersistenceMapper {
    private PasswordDeviceRoutePersistenceMapper() { }

    public static PasswordDeviceRouteEvidence toDomain(PasswordDeviceRouteView view) {
        return new PasswordDeviceRouteEvidence(view.claimedBindingId(), view.lastSuccessfulBindingId(),
                base64(view.installationHash()), Optional.ofNullable(view.candidate())
                        .map(candidate -> toCandidate(candidate, view.deviceProofThumbprint())));
    }

    private static DeviceCandidate toCandidate(DeviceCandidateView view, byte[] proofThumbprint) {
        boolean currentKey = view.keyState() != null && view.keyVersion() != null
                && view.keyThumbprint() != null && proofThumbprint != null
                && MessageDigest.isEqual(proofThumbprint, view.keyThumbprint());
        return new DeviceCandidate(view.bindingId(), view.subjectId(), view.appId(),
                base64(view.installationHash()), "ACTIVE".equals(view.bindingState()), view.expiresAt(),
                currentKey && "ACTIVE".equals(view.keyState()) && view.keyVersion() == 1, currentKey);
    }

    private static String base64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
