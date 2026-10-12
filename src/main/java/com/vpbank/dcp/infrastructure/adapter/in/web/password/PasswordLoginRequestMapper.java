package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.infrastructure.config.properties.PasswordFlowProperties;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import tools.jackson.databind.json.JsonMapper;

/** Maps validated headers and a typed JSON body into the login command. */
public final class PasswordLoginRequestMapper {
    private final URI publicUri;
    private final Duration credentialTimeout;
    private final Duration journeyTimeout;
    private final JsonMapper json;
    private final Clock clock;

    public PasswordLoginRequestMapper(ExternalUriPolicy externalUris,
                                      PasswordFlowProperties policy, JsonMapper json, Clock clock) {
        this.publicUri = Objects.requireNonNull(externalUris).forPath("/api/v1/authentications/password");
        this.credentialTimeout = Duration.ofMillis(policy.credentialDeadlineMs());
        this.journeyTimeout = Duration.ofMillis(policy.journeyDeadlineMs());
        this.json = Objects.requireNonNull(json);
        this.clock = Objects.requireNonNull(clock);
    }

    public PasswordLoginCommand map(PasswordLoginHeaders headers, PasswordLoginRequest body) {
        Objects.requireNonNull(headers, "headers");
        Objects.requireNonNull(body, "body");
        UUID bindingId = body.deviceBindingId() == null ? null : UUID.fromString(body.deviceBindingId());
        PasswordOperationContext operation = new PasswordOperationContext(headers.operationId(),
                body.appId(), body.platform(), body.installationId(), body.username(), bindingId);
        PasswordVerification credential = new PasswordVerification(body.username(), body.password());
        PasswordWireProofs proofs = new PasswordWireProofs(publicUri, headers.dpopProof(),
                body.requestKeyProof(), body.deviceProof(), json.writeValueAsString(body.responseKey().publicJwk()));
        Instant now = clock.instant();
        return new PasswordLoginCommand(operation, credential, proofs, now,
                now.plus(credentialTimeout), now.plus(journeyTimeout));
    }
}
