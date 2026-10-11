package com.vpbank.dcp.infrastructure.adapter.out.redis.codec;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Subject-only guard schema. Device/session guards get separate capability codecs.
 */
public final class SubjectGuardCodec {

    private static final Set<String> FIELDS = Set.of(
            "schemaVersion", "owner", "scope", "generation", "guardVersion",
            "minCustomerSecurityVersion", "minCredentialSecurityVersion",
            "minDeviceSecurityVersion", "customerDenied", "administrativeDenied",
            "resetOperationId");

    public Map<String, String> encode(SubjectGuardSnapshot value) {
        return Map.ofEntries(
                Map.entry("schemaVersion", "1"),
                Map.entry("owner", value.subjectId().toString()),
                Map.entry("scope", "SUBJECT"),
                Map.entry("generation", value.generation().toString()),
                Map.entry("guardVersion", AuthorityNumberCodec.encode(value.guardVersion())),
                Map.entry("minCustomerSecurityVersion",
                        AuthorityNumberCodec.encode(value.floor().customerVersion())),
                Map.entry("minCredentialSecurityVersion",
                        AuthorityNumberCodec.encode(value.floor().credentialVersion())),
                Map.entry("minDeviceSecurityVersion", "0"),
                Map.entry("customerDenied", bit(value.causes().customer())),
                Map.entry("administrativeDenied", bit(value.causes().administrative())),
                Map.entry("resetOperationId", value.causes().resetOperationId()
                        .map(UUID::toString).orElse("")));
    }

    public SubjectGuardSnapshot decode(Map<Object, Object> stored) {
        if (stored == null || stored.size() != FIELDS.size()
                || !stored.keySet().equals(FIELDS)
                || !"1".equals(stored.get("schemaVersion"))
                || !"SUBJECT".equals(stored.get("scope"))
                || !"0".equals(stored.get("minDeviceSecurityVersion"))) {
            throw new InvalidAuthorityValueException();
        }
        String reset = text(stored, "resetOperationId");
        return new SubjectGuardSnapshot(
                AuthorityUuidCodec.decode(text(stored, "owner")),
                AuthorityUuidCodec.decode(text(stored, "generation")),
                AuthorityNumberCodec.decode(text(stored, "guardVersion")),
                new SecurityFloor(
                        AuthorityNumberCodec.decode(text(stored, "minCustomerSecurityVersion")),
                        AuthorityNumberCodec.decode(text(stored, "minCredentialSecurityVersion"))),
                new DenyCauses(bit(text(stored, "customerDenied")),
                        bit(text(stored, "administrativeDenied")),
                        reset.isEmpty() ? Optional.empty() : Optional.of(AuthorityUuidCodec.decode(reset))));
    }

    private String text(Map<Object, Object> stored, String field) {
        if (!(stored.get(field) instanceof String value)) {
            throw new InvalidAuthorityValueException();
        }
        return value;
    }

    private String bit(boolean value) {
        return value ? "1" : "0";
    }

    private boolean bit(String value) {
        return switch (value) {
            case "1" -> true;
            case "0" -> false;
            default -> throw new InvalidAuthorityValueException();
        };
    }
}
