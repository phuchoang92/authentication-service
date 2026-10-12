package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.device.TrustedDeviceRoute;
import com.vpbank.dcp.core.domain.device.TrustedDeviceRouting;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceRouteEvidence;
import com.vpbank.dcp.core.port.out.password.PasswordDeviceRouteRepository;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Classifies the current binding only after provider identity and Customer ownership commit. */
public final class ResolveTrustedDeviceRouteService {

    private final PasswordDeviceRouteRepository routes;
    private final TrustedDeviceRouting routing;

    public ResolveTrustedDeviceRouteService(PasswordDeviceRouteRepository routes,
                                      TrustedDeviceRouting routing) {
        this.routes = Objects.requireNonNull(routes, "routes");
        this.routing = Objects.requireNonNull(routing, "routing");
    }

    public TrustedDeviceRoute resolve(UUID operationId, UUID subjectId, String appId, Instant now) {
        Objects.requireNonNull(now, "now");
        PasswordDeviceRouteEvidence evidence = routes.currentRoute(operationId, subjectId, appId)
                .orElse(null);
        if (evidence == null || (evidence.claimedBindingId() != null
                && evidence.candidate().isEmpty())) {
            return TrustedDeviceRoute.REJECTED;
        }
        return routing.decide(subjectId, appId, evidence.installationHash(),
                evidence.lastSuccessfulBindingId(), evidence.candidate().orElse(null), now);
    }
}
