package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

/** Rejects duplicate JSON members and malformed UTF-8 before a JOSE library parses claims. */
public final class StrictJoseJson {

    private final JsonMapper json = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    public void checkCompactJws(String compact) {
        Objects.requireNonNull(compact, "compact");
        String[] segments = compact.split("\\.", -1);
        if (segments.length != 3 || compact.length() > 16384) {
            throw new InvalidCryptographicInputException();
        }
        checkSegment(segments[0]);
        checkSegment(segments[1]);
    }

    public void checkCompactJweHeader(String compact) {
        Objects.requireNonNull(compact, "compact");
        String[] segments = compact.split("\\.", -1);
        if (segments.length != 5 || compact.length() > 16384) {
            throw new InvalidCryptographicInputException();
        }
        checkSegment(segments[0]);
    }

    public void checkJson(String source) {
        Objects.requireNonNull(source, "source");
        if (source.length() > 16384 || !StandardCharsets.UTF_8.newEncoder().canEncode(source)) {
            throw new InvalidCryptographicInputException();
        }
        try {
            var object = json.readTree(source);
            if (object == null || !object.isObject()) {
                throw new InvalidCryptographicInputException();
            }
        } catch (RuntimeException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }

    private void checkSegment(String segment) {
        if (segment.isEmpty() || !segment.matches("[A-Za-z0-9_-]+")) {
            throw new InvalidCryptographicInputException();
        }
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(segment);
            if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(segment)) {
                throw new InvalidCryptographicInputException();
            }
            String decoded = StandardCharsets.UTF_8.newDecoder()
                    .decode(ByteBuffer.wrap(bytes)).toString();
            checkJson(decoded);
        } catch (IllegalArgumentException | CharacterCodingException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }
}
