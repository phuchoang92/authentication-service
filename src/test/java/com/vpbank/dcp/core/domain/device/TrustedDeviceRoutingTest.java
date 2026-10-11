package com.vpbank.dcp.core.domain.device;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class TrustedDeviceRoutingTest {

    private final TrustedDeviceRouting routing = new TrustedDeviceRouting();
    private final UUID owner = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private final UUID binding = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private final Instant now = Instant.parse("2026-10-11T03:10:00Z");

    @Test
    void noCandidateIsNewDevice() {
        assertEquals(TrustedDeviceRoute.NEW_DEVICE,
                routing.decide(owner, "neo-mobile", "hash", binding, null, now));
    }

    @Test
    void eligibleCurrentBindingIsLastTrusted() {
        assertEquals(TrustedDeviceRoute.LAST_TRUSTED,
                routing.decide(owner, "neo-mobile", "hash", binding, candidate(owner, true), now));
    }

    @Test
    void eligibleDifferentBindingNeedsStepUp() {
        assertEquals(TrustedDeviceRoute.OTHER_TRUSTED,
                routing.decide(owner, "neo-mobile", "hash", UUID.randomUUID(), candidate(owner, true), now));
    }

    @Test
    void wrongOwnerOrMissingProofCannotDowngradeToNewDevice() {
        assertEquals(TrustedDeviceRoute.REJECTED,
                routing.decide(owner, "neo-mobile", "hash", binding,
                        candidate(UUID.randomUUID(), true), now));
        assertEquals(TrustedDeviceRoute.REJECTED,
                routing.decide(owner, "neo-mobile", "hash", binding,
                        candidate(owner, false), now));
    }

    private DeviceCandidate candidate(UUID candidateOwner, boolean proof) {
        return new DeviceCandidate(binding, candidateOwner, "neo-mobile", "hash", true,
                now.plusSeconds(60), true, proof);
    }
}
