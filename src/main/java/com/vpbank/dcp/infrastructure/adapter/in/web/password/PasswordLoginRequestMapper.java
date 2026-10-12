package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import com.vpbank.dcp.infrastructure.config.properties.PasswordFlowProperties;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Checks that the parsed command is exactly the captured public body before admission.
 */
public final class PasswordLoginRequestMapper {
    private static final String PATH = "/api/v1/authentications/password";
    private static final Set<String> JWK_MEMBERS = Set.of("kty", "crv", "x", "y");
    private static final Set<String> BODY_REQUIRED = Set.of("appId", "platform",
            "installationId", "username", "password", "responseKey", "requestKeyProof");
    private static final Set<String> BODY_OPTIONAL = Set.of("deviceBindingId", "deviceProof");
    private static final Set<String> RESPONSE_KEY_MEMBERS = Set.of("version", "algorithm",
            "format", "publicJwk");
    private final ExternalUriPolicy externalUris;
    private final PasswordFlowProperties policy;
    private final JsonMapper json;
    private final Clock clock;

    public PasswordLoginRequestMapper(ExternalUriPolicy externalUris,
                                      PasswordFlowProperties policy, JsonMapper json,
                                      Clock clock) {
        this.externalUris = Objects.requireNonNull(externalUris);
        this.policy = Objects.requireNonNull(policy);
        this.json = Objects.requireNonNull(json);
        this.clock = Objects.requireNonNull(clock);
    }

    public PasswordLoginCommand map(PasswordLoginRequest forwarded) {
        if (forwarded == null || forwarded.original() == null) {
            throw new InvalidPasswordLoginRequestException();
        }
        try {
            var original = forwarded.original();
            if (!"POST".equals(original.method()) || original.opaqueToken() != null
                    || !externalUris.forPath(PATH).equals(URI.create(original.publicUri()))
                    || original.bodyBase64() == null || original.bodyBase64().length() > 87384
                    || !original.bodyBase64().matches("[A-Za-z0-9_-]+")
                    || original.idempotencyKey() == null || original.dpopProof() == null) {
                throw new InvalidPasswordLoginRequestException();
            }
            UUID operationId = UUID.fromString(original.idempotencyKey());
            if (!operationId.toString().equals(original.idempotencyKey())) {
                throw new InvalidPasswordLoginRequestException();
            }
            byte[] body = Base64.getUrlDecoder().decode(original.bodyBase64());
            if (body.length > 65_536 || !Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(body).equals(original.bodyBase64())) {
                throw new InvalidPasswordLoginRequestException();
            }
            JsonNode command = json.readTree(body);
            if (!validMembers(command, BODY_REQUIRED, BODY_OPTIONAL)) {
                throw new InvalidPasswordLoginRequestException();
            }
            String appId = text(command, "appId");
            String platform = text(command, "platform");
            String installationId = text(command, "installationId");
            String username = text(command, "username");
            String password = text(command, "password");
            String requestKeyProof = text(command, "requestKeyProof");
            String deviceProof = optionalText(command, "deviceProof");
            String binding = optionalText(command, "deviceBindingId");
            JsonNode responseKey = command.get("responseKey");
            if (!"neo-mobile".equals(appId) || username.isBlank() || username.length() > 320
                    || password.isEmpty() || password.length() > 1024
                    || installationId.length() < 16 || installationId.length() > 300
                    || !validMembers(responseKey, RESPONSE_KEY_MEMBERS, Set.of())
                    || !responseKey.get("version").isInt()
                    || responseKey.get("version").intValue() != 1
                    || !"ECDH-ES+A256GCM".equals(text(responseKey, "algorithm"))
                    || !"JWK".equals(text(responseKey, "format"))
                    || !validJwk(responseKey.get("publicJwk"))
                    || requestKeyProof.length() > 8192
                    || (deviceProof != null && deviceProof.length() > 8192)) {
                throw new InvalidPasswordLoginRequestException();
            }
            UUID bindingId = binding == null ? null : UUID.fromString(binding);
            var operation = new PasswordOperationContext(operationId, appId,
                    platform, installationId, username, bindingId);
            var credential = new PasswordVerification(username, password);
            var proofs = new PasswordWireProofs(externalUris.forPath(PATH),
                    original.dpopProof(), requestKeyProof, deviceProof,
                    json.writeValueAsString(responseKey.get("publicJwk")));
            Instant now = clock.instant();
            return new PasswordLoginCommand(operation, credential, proofs, now,
                    now.plus(Duration.ofMillis(policy.credentialDeadlineMs())),
                    now.plus(Duration.ofMillis(policy.journeyDeadlineMs())));
        } catch (IllegalArgumentException | JacksonException failure) {
            throw new InvalidPasswordLoginRequestException(failure);
        }
    }

    private boolean validJwk(JsonNode key) {
        return validMembers(key, JWK_MEMBERS, Set.of())
                && "EC".equals(text(key, "kty")) && "P-256".equals(text(key, "crv"))
                && text(key, "x").matches("[A-Za-z0-9_-]{43}")
                && text(key, "y").matches("[A-Za-z0-9_-]{43}");
    }

    private boolean validMembers(JsonNode object, Set<String> required, Set<String> optional) {
        if (object == null || !object.isObject()) {
            return false;
        }
        Set<String> names = Set.copyOf(object.propertyNames());
        return names.containsAll(required) && names.stream()
                .allMatch(name -> required.contains(name) || optional.contains(name));
    }

    private String text(JsonNode object, String name) {
        JsonNode value = object.get(name);
        if (value == null || !value.isTextual()) {
            throw new InvalidPasswordLoginRequestException();
        }
        return value.textValue();
    }

    private String optionalText(JsonNode object, String name) {
        JsonNode value = object.get(name);
        if (value == null || value.isNull()) {
            return null;
        }
        return text(object, name);
    }
}
