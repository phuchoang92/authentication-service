package com.vpbank.dcp.infrastructure.adapter.out.http;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/** Form fields are never exposed through toString, including on a failed exchange. */
public final class ExternalForm {

    private final Map<String, String> fields = new LinkedHashMap<>();

    public ExternalForm add(String name, String value) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(value, "value");
        if (name.isBlank() || fields.putIfAbsent(name, value) != null) {
            throw new InvalidExternalHttpSettingsException();
        }
        return this;
    }

    byte[] bytes() {
        String encoded = fields.entrySet().stream()
                .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                .collect(Collectors.joining("&"));
        return encoded.getBytes(StandardCharsets.UTF_8);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return "ExternalForm[redacted]";
    }
}
