package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.device.DeviceOwnership;
import com.vpbank.dcp.core.domain.totp.TotpCode;
import com.vpbank.dcp.core.port.out.pending.PendingTotpLogin;
import com.vpbank.dcp.core.port.out.totp.CheckDeviceTotp;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpCheckResult;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpUnavailableException;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpVerifier;
import com.vpbank.dcp.core.port.out.totp.InvalidTotpProofException;
import com.vpbank.dcp.core.port.out.totp.TotpProofReader;
import java.time.Instant;
import java.util.Objects;

/** Decrypts the challenge-bound JWE and consumes a TOTP time step under the DB row lock. */
public final class CheckTotpChallengeService {
    private final TotpProofReader proofs;
    private final DeviceTotpVerifier credentials;

    public CheckTotpChallengeService(TotpProofReader proofs, DeviceTotpVerifier credentials) {
        this.proofs = Objects.requireNonNull(proofs);
        this.credentials = Objects.requireNonNull(credentials);
    }

    public TotpChallengeResult check(PendingTotpLogin pending, String proofJwe, Instant now) {
        Objects.requireNonNull(pending);
        Objects.requireNonNull(now);
        if (!now.isBefore(pending.challenge().expiresAt())) {
            return TotpChallengeResult.REJECTED;
        }
        try (TotpCode code = proofs.read(proofJwe, pending.challenge().challengeId(),
                pending.keys().requestKeyJkt(), now)) {
            var owner = new DeviceOwnership(pending.identity().customerId(), pending.identity().channel());
            var command = new CheckDeviceTotp(owner, pending.identity().bindingId(), code);
            return credentials.verify(command) == DeviceTotpCheckResult.ACCEPTED
                    ? TotpChallengeResult.ACCEPTED : TotpChallengeResult.REJECTED;
        } catch (InvalidTotpProofException failure) {
            return TotpChallengeResult.REJECTED;
        } catch (DeviceTotpUnavailableException failure) {
            return TotpChallengeResult.UNAVAILABLE;
        }
    }
}
