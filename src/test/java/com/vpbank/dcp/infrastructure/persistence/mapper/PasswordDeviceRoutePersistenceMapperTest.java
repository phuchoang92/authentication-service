package com.vpbank.dcp.infrastructure.persistence.mapper;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.infrastructure.persistence.projection.DeviceCandidateView;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordDeviceRouteView;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class PasswordDeviceRoutePersistenceMapperTest {
    private final UUID bindingId = UUID.randomUUID();
    private final UUID subjectId = UUID.randomUUID();
    private final UUID lastSuccessfulId = UUID.randomUUID();
    private final byte[] installation = new byte[32];
    private final byte[] thumbprint = new byte[32];
    private final Instant expiry = Instant.parse("2026-10-12T14:30:00.123456Z");

    @Test
    void missingClaimedBindingAndCandidateStayAbsent() {
        var route = PasswordDeviceRoutePersistenceMapper.toDomain(
                new PasswordDeviceRouteView(null, null, installation, null, null));
        assertThat(route.claimedBindingId()).isNull();
        assertThat(route.lastSuccessfulBindingId()).isNull();
        assertThat(route.candidate()).isEmpty();
        assertThat(route.installationHash()).isEqualTo(Base64.getUrlEncoder().withoutPadding()
                .encodeToString(installation));
    }

    @Test
    void restoresDistinctOwnersAndExactPinnedKeyEvidence() {
        var candidate = new DeviceCandidateView(bindingId, subjectId, "mobile", installation,
                "ACTIVE", expiry, "ACTIVE", 1, thumbprint);
        var route = PasswordDeviceRoutePersistenceMapper.toDomain(new PasswordDeviceRouteView(
                bindingId, lastSuccessfulId, installation, thumbprint, candidate));
        assertThat(route.claimedBindingId()).isEqualTo(bindingId);
        assertThat(route.lastSuccessfulBindingId()).isEqualTo(lastSuccessfulId);
        var restored = route.candidate().orElseThrow();
        assertThat(restored.ownerId()).isEqualTo(subjectId);
        assertThat(restored.bindingId()).isEqualTo(bindingId);
        assertThat(restored.appId()).isEqualTo("mobile");
        assertThat(restored.expiresAt()).isEqualTo(expiry);
        assertThat(restored.active()).isTrue();
        assertThat(restored.keyActive()).isTrue();
        assertThat(restored.possessionVerified()).isTrue();
    }

    @Test
    void wrongOrMissingProofCannotBecomeVerifiedPossession() {
        byte[] wrongProof = thumbprint.clone();
        wrongProof[31] = 1;
        var candidate = new DeviceCandidateView(bindingId, subjectId, "mobile", installation,
                "ACTIVE", expiry, "ACTIVE", 1, thumbprint);
        for (byte[] proof : new byte[][]{wrongProof, null}) {
            var restored = PasswordDeviceRoutePersistenceMapper.toDomain(new PasswordDeviceRouteView(
                    bindingId, lastSuccessfulId, installation, proof, candidate)).candidate().orElseThrow();
            assertThat(restored.possessionVerified()).isFalse();
            assertThat(restored.keyActive()).isFalse();
        }
    }

    @Test
    void inactiveUnknownOrIncompleteKeysDoNotBecomeActive() {
        for (String state : new String[]{"REVOKED", "unknown", null}) {
            var candidate = new DeviceCandidateView(bindingId, subjectId, "mobile", installation,
                    "REVOKED", expiry, state, 1, thumbprint);
            var restored = PasswordDeviceRoutePersistenceMapper.toDomain(new PasswordDeviceRouteView(
                    bindingId, lastSuccessfulId, installation, thumbprint, candidate)).candidate().orElseThrow();
            assertThat(restored.active()).isFalse();
            assertThat(restored.keyActive()).isFalse();
            assertThat(restored.possessionVerified()).isEqualTo(state != null);
        }
        for (Integer version : new Integer[]{null, 2}) {
            var candidate = new DeviceCandidateView(bindingId, subjectId, "mobile", installation,
                    "ACTIVE", expiry, "ACTIVE", version, thumbprint);
            assertThat(PasswordDeviceRoutePersistenceMapper.toDomain(new PasswordDeviceRouteView(
                    bindingId, lastSuccessfulId, installation, thumbprint, candidate))
                    .candidate().orElseThrow().keyActive()).isFalse();
        }
    }
}
