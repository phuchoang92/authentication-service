package com.vpbank.dcp.infrastructure.persistence.codec;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.core.domain.device.DeviceOwnership;
import com.vpbank.dcp.core.domain.device.DeviceRevocationReason;
import com.vpbank.dcp.core.domain.device.SecurityActor;
import com.vpbank.dcp.core.domain.device.SecurityActorType;
import com.vpbank.dcp.core.port.out.device.RecordDeviceRevocation;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class DeviceRevocationCommandDigestTest {
    private final DeviceRevocationCommandDigest digests = new DeviceRevocationCommandDigest();

    @Test
    void digestIsDeterministicAndBindsEveryCommandField() {
        RecordDeviceRevocation original = command();
        byte[] expected = digests.calculate(original);
        assertThat(expected).hasSize(32).isEqualTo(digests.calculate(original));

        assertDifferent(original, new RecordDeviceRevocation(
                new DeviceOwnership(new SubjectId(UUID.randomUUID()), original.owner().channel()),
                original.bindingId(), original.operationId(), original.expectedVersion(),
                original.reason(), original.actor(), original.occurredAt()));
        assertDifferent(original, new RecordDeviceRevocation(
                new DeviceOwnership(original.owner().subject(), "another-channel"),
                original.bindingId(), original.operationId(), original.expectedVersion(),
                original.reason(), original.actor(), original.occurredAt()));
        assertDifferent(original, new RecordDeviceRevocation(original.owner(), new BindingId(UUID.randomUUID()),
                original.operationId(), original.expectedVersion(), original.reason(),
                original.actor(), original.occurredAt()));
        assertDifferent(original, new RecordDeviceRevocation(original.owner(), original.bindingId(),
                UUID.randomUUID(), original.expectedVersion(), original.reason(),
                original.actor(), original.occurredAt()));
        assertDifferent(original, new RecordDeviceRevocation(original.owner(), original.bindingId(),
                original.operationId(), original.expectedVersion() + 1, original.reason(),
                original.actor(), original.occurredAt()));
        assertDifferent(original, new RecordDeviceRevocation(original.owner(), original.bindingId(),
                original.operationId(), original.expectedVersion(), DeviceRevocationReason.STOLEN,
                original.actor(), original.occurredAt()));
        assertDifferent(original, new RecordDeviceRevocation(original.owner(), original.bindingId(),
                original.operationId(), original.expectedVersion(), original.reason(),
                new SecurityActor(SecurityActorType.SYSTEM, original.actor().id()),
                original.occurredAt()));
        assertDifferent(original, new RecordDeviceRevocation(original.owner(), original.bindingId(),
                original.operationId(), original.expectedVersion(), original.reason(),
                new SecurityActor(original.actor().type(), "other-actor"),
                original.occurredAt()));
        assertDifferent(original, new RecordDeviceRevocation(original.owner(), original.bindingId(),
                original.operationId(), original.expectedVersion(), original.reason(),
                original.actor(), original.occurredAt().plusNanos(1)));
    }

    private void assertDifferent(RecordDeviceRevocation first, RecordDeviceRevocation second) {
        assertThat(digests.calculate(second)).isNotEqualTo(digests.calculate(first));
    }

    private RecordDeviceRevocation command() {
        return new RecordDeviceRevocation(new DeviceOwnership(new SubjectId(UUID.randomUUID()), "neo-mobile"),
                new BindingId(UUID.randomUUID()), UUID.randomUUID(), 7,
                DeviceRevocationReason.CUSTOMER_REQUEST,
                new SecurityActor(SecurityActorType.CUSTOMER, "customer-1"),
                Instant.parse("2026-10-13T02:00:00.123456789Z"));
    }
}
