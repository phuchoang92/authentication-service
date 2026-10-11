package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import com.vpbank.dcp.core.application.password.PasswordAdmissionCommand;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.infrastructure.config.properties.PasswordFlowProperties;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import tools.jackson.databind.json.JsonMapper;

/** Checks that the parsed command is exactly the captured public body before admission. */
public final class ForwardPasswordRequestMapper {
    private static final String PATH = "/api/v1/authentications/password";
    private static final Set<String> JWK_MEMBERS = Set.of("kty", "crv", "x", "y");
    private final ExternalUriPolicy externalUris;
    private final PasswordFlowProperties policy;
    private final JsonMapper json;
    private final Clock clock;

    public ForwardPasswordRequestMapper(ExternalUriPolicy externalUris,
                                        PasswordFlowProperties policy, JsonMapper json,
                                        Clock clock) {
        this.externalUris = Objects.requireNonNull(externalUris);
        this.policy = Objects.requireNonNull(policy);
        this.json = Objects.requireNonNull(json);
        this.clock = Objects.requireNonNull(clock);
    }

    public PasswordAdmissionCommand map(ForwardPasswordRequest forwarded) {
        if (forwarded == null || forwarded.original() == null || forwarded.command() == null) {
            throw new InvalidForwardPasswordRequestException();
        }
        try {
            var original = forwarded.original();
            var command = forwarded.command();
            if (!"POST".equals(original.method()) || original.opaqueToken() != null
                    || !externalUris.forPath(PATH).equals(URI.create(original.publicUri()))
                    || original.bodyBase64() == null || original.bodyBase64().length() > 87384
                    || !original.bodyBase64().matches("[A-Za-z0-9_-]+")
                    || original.idempotencyKey() == null || original.dpopProof() == null) {
                throw new InvalidForwardPasswordRequestException();
            }
            UUID operationId = UUID.fromString(original.idempotencyKey());
            if (!operationId.toString().equals(original.idempotencyKey())) {
                throw new InvalidForwardPasswordRequestException();
            }
            byte[] body = Base64.getUrlDecoder().decode(original.bodyBase64());
            if (body.length > 65_536 || !Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(body).equals(original.bodyBase64())) {
                throw new InvalidForwardPasswordRequestException();
            }
            ForwardPasswordRequest.Command captured = json.readValue(body,
                    ForwardPasswordRequest.Command.class);
            if (!captured.equals(command) || !"neo-mobile".equals(command.appId())
                    || command.username() == null || command.username().isBlank()
                    || command.username().length() > 320 || command.password() == null
                    || command.password().isEmpty() || command.password().length() > 1024
                    || command.installationId() == null
                    || command.installationId().length() < 16
                    || command.installationId().length() > 300
                    || command.responseKey() == null
                    || !Integer.valueOf(1).equals(command.responseKey().version())
                    || !"ECDH-ES+A256GCM".equals(command.responseKey().algorithm())
                    || !"JWK".equals(command.responseKey().format())
                    || !validJwk(command.responseKey().publicJwk())
                    || command.requestKeyProof() == null
                    || command.requestKeyProof().length() > 8192
                    || (command.deviceProof() != null && command.deviceProof().length() > 8192)) {
                throw new InvalidForwardPasswordRequestException();
            }
            UUID bindingId = command.deviceBindingId() == null ? null
                    : UUID.fromString(command.deviceBindingId());
            var operation = new PasswordOperationContext(operationId, command.appId(),
                    command.platform(), command.installationId(), command.username(), bindingId);
            var credential = new PasswordVerification(command.username(), command.password());
            var proofs = new PasswordWireProofs(externalUris.forPath(PATH),
                    original.dpopProof(), command.requestKeyProof(), command.deviceProof(),
                    json.writeValueAsString(command.responseKey().publicJwk()));
            Instant now = clock.instant();
            return new PasswordAdmissionCommand(operation, credential, proofs, now,
                    now.plus(Duration.ofMillis(policy.credentialDeadlineMs())),
                    now.plus(Duration.ofMillis(policy.journeyDeadlineMs())));
        } catch (IllegalArgumentException failure) {
            throw new InvalidForwardPasswordRequestException(failure);
        }
    }

    private boolean validJwk(Map<String, String> key) {
        return key != null && key.keySet().equals(JWK_MEMBERS)
                && "EC".equals(key.get("kty")) && "P-256".equals(key.get("crv"))
                && key.get("x") != null && key.get("x").matches("[A-Za-z0-9_-]{43}")
                && key.get("y") != null && key.get("y").matches("[A-Za-z0-9_-]{43}");
    }
}
