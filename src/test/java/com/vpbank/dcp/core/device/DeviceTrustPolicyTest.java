package com.vpbank.dcp.core.device;

import com.vpbank.dcp.core.customer.SubjectId;
import com.vpbank.dcp.core.security.Digest32;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class DeviceTrustPolicyTest {

    private final DeviceTrustPolicy routing = new DeviceTrustPolicy();
    private final SubjectId owner = new SubjectId(UUID.fromString("11111111-1111-4111-8111-111111111111"));
    private final DeviceOwnership mine = new DeviceOwnership(owner, "neo-mobile");
    private final BindingId binding = new BindingId(UUID.fromString("22222222-2222-4222-8222-222222222222"));
    private final Digest32 storedKey = digest(1);
    private final Instant now = Instant.parse("2026-10-11T03:10:00Z");

    @Test
    void noCandidateIsNewDevice() {
        assertEquals(DeviceTrustDecision.NEW_DEVICE,
                routing.decide(mine, "ANDROID", null, storedKey, now));
    }

    @Test
    void eligibleCurrentBindingIsLastTrusted() {
        assertEquals(DeviceTrustDecision.LAST_TRUSTED,
                routing.decide(mine, "ANDROID", stored(owner, true), storedKey, now));
    }

    @Test
    void eligibleDifferentBindingNeedsStepUp() {
        assertEquals(DeviceTrustDecision.OTHER_TRUSTED,
                routing.decide(mine, "ANDROID", stored(owner, false), storedKey, now));
    }

    @Test
    void wrongOwnerOrMissingProofCannotDowngradeToNewDevice() {
        assertEquals(DeviceTrustDecision.REJECTED, routing.decide(mine, "ANDROID",
                stored(new SubjectId(UUID.randomUUID()), true), storedKey, now));
        assertEquals(DeviceTrustDecision.REJECTED, routing.decide(mine, "ANDROID",
                stored(owner, true), digest(2), now));
        assertEquals(DeviceTrustDecision.REJECTED, routing.decide(mine, "ANDROID",
                stored(owner, true), null, now));
    }

    @Test
    void revokedOrExpiredProvenBindingLapsesInsteadOfBeingRejected() {
        assertEquals(DeviceTrustDecision.TRUST_LAPSED, routing.decide(mine, "ANDROID",
                stored(owner, true, false, now.plusSeconds(60)), storedKey, now));
        assertEquals(DeviceTrustDecision.TRUST_LAPSED, routing.decide(mine, "ANDROID",
                stored(owner, false, true, now), storedKey, now));
    }

    /** Lapsing never skips the identity checks: a foreign or unproven binding is rejected. */
    @Test
    void lapsedBindingThatIsForeignOrUnprovenIsStillRejected() {
        Instant expired = now.minusSeconds(1);
        assertEquals(DeviceTrustDecision.REJECTED, routing.decide(mine, "ANDROID",
                stored(new SubjectId(UUID.randomUUID()), true, false, expired), storedKey, now));
        assertEquals(DeviceTrustDecision.REJECTED, routing.decide(mine, "ANDROID",
                stored(owner, true, false, expired), digest(2), now));
        assertEquals(DeviceTrustDecision.REJECTED, routing.decide(
                new DeviceOwnership(owner, "other-channel"), "ANDROID",
                stored(owner, true, false, expired), storedKey, now));
    }

    private LoginDeviceSnapshot stored(SubjectId rowOwner, boolean primary) {
        return stored(rowOwner, primary, true, now.plusSeconds(60));
    }

    private LoginDeviceSnapshot stored(SubjectId rowOwner, boolean primary, boolean active,
                                       Instant expiresAt) {
        return new LoginDeviceSnapshot(binding, new DeviceOwnership(rowOwner, "neo-mobile"),
                "ANDROID", true, new DeviceStanding(active, expiresAt, primary), 0,
                new StoredDeviceKey(new byte[]{1}, storedKey));
    }

    private static Digest32 digest(int fill) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) fill);
        return Digest32.fromBytes(bytes);
    }
}
