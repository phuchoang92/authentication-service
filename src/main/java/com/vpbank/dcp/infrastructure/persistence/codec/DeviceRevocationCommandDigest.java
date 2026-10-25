package com.vpbank.dcp.infrastructure.persistence.codec;

import com.vpbank.dcp.core.device.RecordDeviceRevocation;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.springframework.stereotype.Component;

/** Stable fingerprint of the complete revocation command, independent of SQL timestamps. */
@Component
public final class DeviceRevocationCommandDigest {
    private static final String VERSION = "BANK_DEVICE_REVOKE_COMMAND_V1";

    public byte[] calculate(RecordDeviceRevocation command) {
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        append(encoded, VERSION);
        append(encoded, command.owner().subject().value().toString());
        append(encoded, command.owner().channel());
        append(encoded, command.bindingId().value().toString());
        append(encoded, command.operationId().toString());
        append(encoded, Long.toString(command.expectedVersion()));
        append(encoded, command.reason().code());
        append(encoded, command.actor().type().code());
        append(encoded, command.actor().id());
        append(encoded, Long.toString(command.occurredAt().getEpochSecond()));
        append(encoded, Integer.toString(command.occurredAt().getNano()));
        try {
            return MessageDigest.getInstance("SHA-256").digest(encoded.toByteArray());
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static void append(ByteArrayOutputStream encoded, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        encoded.writeBytes(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
        encoded.writeBytes(bytes);
    }
}
