package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

/** Encodes each contract field as a four-byte big-endian length and exact UTF-8 bytes. */
public final class ChallengeSigningInput {

    public byte[] encode(List<String> fields) {
        Objects.requireNonNull(fields, "fields");
        if (fields.isEmpty() || fields.size() > 24) {
            throw new InvalidCryptographicInputException();
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (String field : fields) {
            Objects.requireNonNull(field, "field");
            if (!StandardCharsets.UTF_8.newEncoder().canEncode(field)) {
                throw new InvalidCryptographicInputException();
            }
            byte[] value = field.getBytes(StandardCharsets.UTF_8);
            if (value.length > 4096) {
                throw new InvalidCryptographicInputException();
            }
            output.writeBytes(ByteBuffer.allocate(4).putInt(value.length).array());
            output.writeBytes(value);
        }
        return output.toByteArray();
    }
}
