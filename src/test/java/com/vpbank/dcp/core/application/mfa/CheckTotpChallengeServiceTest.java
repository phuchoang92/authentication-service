package com.vpbank.dcp.core.application.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.totp.TotpCode;
import com.vpbank.dcp.core.port.out.pending.PendingTotpLogin;
import com.vpbank.dcp.core.port.out.totp.CheckDeviceTotp;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpCheckResult;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpVerifier;
import com.vpbank.dcp.core.port.out.totp.InvalidTotpProofException;
import com.vpbank.dcp.core.port.out.totp.TotpProofReader;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CheckTotpChallengeServiceTest {
    private final TotpProofReader proofs = mock(TotpProofReader.class);
    private final DeviceTotpVerifier credentials = mock(DeviceTotpVerifier.class);
    private final CheckTotpChallengeService service = new CheckTotpChallengeService(proofs, credentials);
    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");

    @Test
    void validJweAndCurrentCredentialAcceptOnce() {
        PendingTotpLogin pending = pending(now.plusSeconds(120));
        TotpCode code = new TotpCode("123456".toCharArray());
        when(proofs.read("encrypted-proof", pending.challenge().challengeId(),
                pending.keys().requestKeyJkt(), now)).thenReturn(code);
        when(credentials.verify(any(CheckDeviceTotp.class))).thenReturn(DeviceTotpCheckResult.ACCEPTED);

        assertThat(service.check(pending, "encrypted-proof", now)).isEqualTo(TotpChallengeResult.ACCEPTED);
        verify(credentials).verify(any(CheckDeviceTotp.class));
        assertThat(code.copyDigits()).containsOnly('\0');
    }

    @Test
    void invalidProofAndExpiredChallengeNeverReachCredential() {
        PendingTotpLogin pending = pending(now.plusSeconds(120));
        when(proofs.read("bad-proof", pending.challenge().challengeId(),
                pending.keys().requestKeyJkt(), now)).thenThrow(new InvalidTotpProofException());
        assertThat(service.check(pending, "bad-proof", now)).isEqualTo(TotpChallengeResult.REJECTED);
        assertThat(service.check(pending(now), "encrypted-proof", now))
                .isEqualTo(TotpChallengeResult.REJECTED);
        verify(credentials, never()).verify(any());
    }

    private PendingTotpLogin pending(Instant expiresAt) {
        String id = "QkJCQkJCQkJCQkJCQkJCQg";
        return new PendingTotpLogin(
                new PendingTotpLogin.Identity(UUID.randomUUID(), UUID.randomUUID(), "customer-a",
                        UUID.randomUUID(), "neo-mobile", "installation-1234567890"),
                new PendingTotpLogin.Keys("request-jkt", "request-jwk", "response-jwk", "device-jkt"),
                new PendingTotpLogin.Challenge(id, id, expiresAt),
                new PendingTotpLogin.Versions(1, 2, UUID.randomUUID()));
    }
}
