package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.credential.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginRequest;
import com.vpbank.dcp.infrastructure.config.properties.PasswordFlowProperties;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import tools.jackson.databind.json.JsonMapper;

/** Maps validated headers and a typed JSON body into the login command. */
public final class PasswordLoginRequestMapper {
    private final Duration credentialTimeout;
    private final Duration journeyTimeout;
    private final JsonMapper json;
    private final Clock clock;

    public PasswordLoginRequestMapper(PasswordFlowProperties policy, JsonMapper json, Clock clock) {
        this.credentialTimeout = Duration.ofMillis(policy.credentialDeadlineMs());
        this.journeyTimeout = Duration.ofMillis(policy.journeyDeadlineMs());
        this.json = Objects.requireNonNull(json);
        this.clock = Objects.requireNonNull(clock);
    }

    public PasswordLoginCommand map(PasswordLoginHeaders headers, PasswordLoginRequest body, VerifiedDpopProof dpop) {
        Objects.requireNonNull(headers, "headers");
        Objects.requireNonNull(body, "body");
        PasswordOperationContext operation = new PasswordOperationContext(headers.operationId(),
                body.appId(), body.platform(), body.installationId(), body.username(),
                body.deviceBindingId());
        PasswordVerification credential = new PasswordVerification(body.username(), body.password());
        PasswordWireProofs proofs = new PasswordWireProofs(dpop,
                body.requestKeyProof(), body.deviceProof(), json.writeValueAsString(body.tokenEncryptionKey().publicJwk()));
        Instant now = clock.instant();
        return new PasswordLoginCommand(operation, credential, proofs, now,
                now.plus(credentialTimeout), now.plus(journeyTimeout));
    }
}
