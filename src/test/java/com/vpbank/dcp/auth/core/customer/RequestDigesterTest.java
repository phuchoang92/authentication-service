package com.vpbank.dcp.auth.core.customer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class RequestDigesterTest {
    private final RequestDigester digester = new RequestDigester(key(1));

    @Test
    void sameRequestGivesTheSameDigest() {
        assertThat(digester.digest(command("Alice", "Nguyen", null)))
                .isEqualTo(digester.digest(command("Alice", "Nguyen", null)));
    }

    @Test
    void movingCharactersBetweenFieldsChangesTheDigest() {
        assertThat(digester.digest(command("Alic", "eNguyen", null)))
                .isNotEqualTo(digester.digest(command("Alice", "Nguyen", null)));
    }

    @Test
    void aMissingEmailDiffersFromAnEmptyLookingOne() {
        assertThat(digester.digest(command("Alice", "Nguyen", "a@b.c")))
                .isNotEqualTo(digester.digest(command("Alice", "Nguyen", null)));
    }

    @Test
    void anotherKeyGivesAnotherDigest() {
        assertThat(new RequestDigester(key(2)).digest(command("Alice", "Nguyen", null)))
                .isNotEqualTo(digester.digest(command("Alice", "Nguyen", null)));
    }

    @Test
    void aShortKeyIsRejected() {
        assertThatThrownBy(() -> new RequestDigester(new byte[16])).isInstanceOf(IllegalArgumentException.class);
    }

    private static RegistrationCommand command(String first, String last, String email) {
        return new RegistrationCommand("90359", "alice", first, last, "+84901234567", email);
    }

    private static byte[] key(int fill) {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) fill);
        return key;
    }
}
