package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import java.util.Map;
import java.util.stream.Collectors;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * A public JWK crosses the API as a JSON object and crosses the ports as text: the sealers parse
 * and validate it. Only flat objects with string members are public JWKs we accept, so the text
 * form is minimal and canonical here (member order as sent).
 */
public final class JwkJson {
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final TypeReference<Map<String, Object>> FLAT_OBJECT = new TypeReference<>() {
    };

    private JwkJson() {
    }

    /** @throws IllegalArgumentException when a member is not a string (a nested or numeric member) */
    public static String toJson(Map<String, Object> jwk) {
        boolean flat = jwk.values().stream().allMatch(value -> value instanceof String);
        if (!flat) {
            throw new IllegalArgumentException("A public JWK must be a flat object of strings");
        }
        return jwk.entrySet().stream()
                .map(member -> "\"" + escape(member.getKey()) + "\":\"" + escape((String) member.getValue()) + "\"")
                .collect(Collectors.joining(",", "{", "}"));
    }

    /** The server-side JWK text (produced by Nimbus) back to a JSON object for the response body. */
    public static Map<String, Object> toMap(String jwkJson) {
        try {
            return JSON.readValue(jwkJson, FLAT_OBJECT);
        } catch (JacksonException malformed) {
            throw new IllegalStateException("Server JWK is not a JSON object", malformed);
        }
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
