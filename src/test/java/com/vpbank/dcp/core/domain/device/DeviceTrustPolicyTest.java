package com.vpbank.dcp.core.domain.device;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class DeviceTrustPolicyTest {

    private final DeviceTrustPolicy routing = new DeviceTrustPolicy();
    private final SubjectId owner = new SubjectId(UUID.fromString("11111111-1111-4111-8111-111111111111"));
    private final BindingId binding = new BindingId(UUID.fromString("22222222-2222-4222-8222-222222222222"));
    private final Instant now = Instant.parse("2026-10-11T03:10:00Z");

    @Test
    void noCandidateIsNewDevice() {
        assertEquals(DeviceTrustDecision.NEW_DEVICE,
                routing.decide(owner, "neo-mobile", "ANDROID", null, now));
    }

    @Test
    void eligibleCurrentBindingIsLastTrusted() {
        assertEquals(DeviceTrustDecision.LAST_TRUSTED,
                routing.decide(owner, "neo-mobile", "ANDROID", candidate(owner, true, true), now));
    }

    @Test
    void eligibleDifferentBindingNeedsStepUp() {
        assertEquals(DeviceTrustDecision.OTHER_TRUSTED,
                routing.decide(owner, "neo-mobile", "ANDROID", candidate(owner, true, false), now));
    }

    @Test
    void wrongOwnerOrMissingProofCannotDowngradeToNewDevice() {
        assertEquals(DeviceTrustDecision.REJECTED,
                routing.decide(owner, "neo-mobile", "ANDROID",
                        candidate(new SubjectId(UUID.randomUUID()), true, true), now));
        assertEquals(DeviceTrustDecision.REJECTED,
                routing.decide(owner, "neo-mobile", "ANDROID",
                        candidate(owner, false, true), now));
    }

    @Test
    void revokedOrExpiredProvenBindingLapsesInsteadOfBeingRejected() {
        assertEquals(DeviceTrustDecision.TRUST_LAPSED, routing.decide(owner, "neo-mobile",
                "ANDROID", candidate(owner, true, true, false, now.plusSeconds(60)), now));
        assertEquals(DeviceTrustDecision.TRUST_LAPSED, routing.decide(owner, "neo-mobile",
                "ANDROID", candidate(owner, true, false, true, now), now));
    }

    /** Lapsing never skips the identity checks: a foreign or unproven binding is rejected. */
    @Test
    void lapsedBindingThatIsForeignOrUnprovenIsStillRejected() {
        Instant expired = now.minusSeconds(1);
        assertEquals(DeviceTrustDecision.REJECTED, routing.decide(owner, "neo-mobile", "ANDROID",
                candidate(new SubjectId(UUID.randomUUID()), true, true, false, expired), now));
        assertEquals(DeviceTrustDecision.REJECTED, routing.decide(owner, "neo-mobile", "ANDROID",
                candidate(owner, false, true, false, expired), now));
        assertEquals(DeviceTrustDecision.REJECTED, routing.decide(owner, "other-channel",
                "ANDROID", candidate(owner, true, true, false, expired), now));
    }

    private DeviceCandidate candidate(SubjectId candidateOwner, boolean proof, boolean primary) {
        return candidate(candidateOwner, proof, primary, true, now.plusSeconds(60));
    }

    private DeviceCandidate candidate(SubjectId candidateOwner, boolean proof, boolean primary,
                                      boolean active, Instant expiresAt) {
        return new DeviceCandidate(binding, candidateOwner, "neo-mobile", "ANDROID", true,
                active, primary, expiresAt, proof);
    }
}
