package com.vpbank.dcp.infrastructure.persistence.projection;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class PersistenceProjectionTest {
    @ParameterizedTest
    @MethodSource("protectedViews")
    void byteValuesAreImmutableContentEqualAndRedacted(Record view) throws ReflectiveOperationException {
        RecordComponent[] components = view.getClass().getRecordComponents();
        Class<?>[] types = Arrays.stream(components).map(RecordComponent::getType).toArray(Class<?>[]::new);
        Object[] arguments = new Object[components.length];
        for (int i = 0; i < components.length; i++) {
            arguments[i] = components[i].getAccessor().invoke(view);
        }
        Record copy = (Record) view.getClass().getConstructor(types).newInstance(arguments);
        assertThat(copy).isEqualTo(view);
        assertThat(copy.hashCode()).isEqualTo(view.hashCode());
        assertThat(copy.toString()).isEqualTo(view.getClass().getSimpleName() + "[redacted]");
        for (int i = 0; i < components.length; i++) {
            if (types[i] == byte[].class && arguments[i] != null) {
                byte[] expected = ((byte[]) arguments[i]).clone();
                ((byte[]) arguments[i])[0] ^= 1;
                byte[] exposed = (byte[]) components[i].getAccessor().invoke(copy);
                assertThat(exposed).isEqualTo(expected);
                exposed[0] ^= 2;
                assertThat((byte[]) components[i].getAccessor().invoke(copy)).isEqualTo(expected);
                assertThat(copy).isEqualTo(view);
            }
        }
        Record changed = (Record) view.getClass().getConstructor(types).newInstance(arguments);
        assertThat(changed).isNotEqualTo(view);
    }

    static Stream<Record> protectedViews() {
        UUID id = UUID.randomUUID();
        byte[] digest = new byte[32];
        Instant time = Instant.parse("2026-10-12T14:00:00Z");
        var candidate = new DeviceCandidateView(id, id, "mobile", digest, "ACTIVE", time,
                "ACTIVE", 1, digest);
        return Stream.of(
                new PasswordReservationView(id, id, digest, "key-1"),
                new StoredDeviceKeyView(new byte[]{1, 2, 3}, digest),
                candidate,
                new PasswordDeviceRouteView(id, id, digest, digest, candidate),
                new PasswordSessionFactsView(id, id, id, "mobile", id, digest, "request", "response",
                        digest, 1, 2, 3, 4, time, "NONE", false),
                new PreparedPasswordSessionView(id, id, id, "key-1", digest, digest,
                        time, time, time, new byte[]{1, 2, 3}, digest, 1, 2, 3, digest, id, id));
    }
}
