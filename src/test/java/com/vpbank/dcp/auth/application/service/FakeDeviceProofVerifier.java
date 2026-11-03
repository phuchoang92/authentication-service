package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.gateway.DeviceProofVerifier;
import com.vpbank.dcp.auth.application.port.out.model.DeviceProofBindings;
import com.vpbank.dcp.auth.domain.model.DeviceProof;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Test double with the verifier's contract: a proof registered with {@link #accept} is proven under the stored
 * key it was registered for, bound to the bindings it was registered with; anything else is rejected.
 */
final class FakeDeviceProofVerifier implements DeviceProofVerifier {
    private record Accepted(String devicePublicJwk, DeviceProofBindings bindings, Outcome.Proven outcome) { }

    private final Map<DeviceProof, Accepted> accepted = new HashMap<>();
    final List<DeviceProofBindings> seen = new ArrayList<>();

    void accept(DeviceProof proof, String devicePublicJwk, DeviceProofBindings bindings, Instant rememberUntil) {
        accepted.put(proof, new Accepted(devicePublicJwk, bindings, new Outcome.Proven(rememberUntil)));
    }

    @Override
    public Outcome verify(String devicePublicJwk, DeviceProof proof, DeviceProofBindings bindings) {
        // The port's contract, like the real verifier: the caller never passes a missing proof.
        java.util.Objects.requireNonNull(proof, "proof");
        seen.add(bindings);
        Accepted match = accepted.get(proof);
        boolean sameKeyAndLogin = match != null
                && match.devicePublicJwk().equals(devicePublicJwk)
                && match.bindings().equals(bindings);
        return sameKeyAndLogin ? match.outcome() : new Outcome.Rejected();
    }
}
