package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.gateway.DeviceProofVerifier;
import com.vpbank.dcp.auth.application.port.out.model.DeviceProofBindings;
import com.vpbank.dcp.auth.domain.model.DeviceSigningKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Test double with the verifier's contract: a proof text registered with {@link #accept} is proven under the
 * key it was registered with, bound to the bindings it was registered with; anything else is rejected.
 */
final class FakeDeviceProofVerifier implements DeviceProofVerifier {
    private record Accepted(String devicePublicJwk, DeviceProofBindings bindings, Outcome.Proven outcome) { }

    private final Map<String, Accepted> accepted = new HashMap<>();
    final List<DeviceProofBindings> seen = new ArrayList<>();

    void accept(String proof, String devicePublicJwk, DeviceProofBindings bindings, DeviceSigningKey key,
                String proofId, Instant rememberUntil) {
        accepted.put(proof, new Accepted(devicePublicJwk, bindings, new Outcome.Proven(key, proofId, rememberUntil)));
    }

    @Override
    public Outcome verify(String devicePublicJwk, String compactProof, DeviceProofBindings bindings) {
        seen.add(bindings);
        Accepted match = accepted.get(compactProof);
        boolean sameKeyAndLogin = match != null
                && match.devicePublicJwk().equals(devicePublicJwk)
                && match.bindings().equals(bindings);
        return sameKeyAndLogin ? match.outcome() : new Outcome.Rejected();
    }
}
