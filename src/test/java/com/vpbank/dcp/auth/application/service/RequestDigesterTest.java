package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.command.RegisterCustomerCommand;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.Email;
import com.vpbank.dcp.auth.domain.model.PhoneNumber;
import com.vpbank.dcp.auth.domain.model.UserName;
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
    void aMissingEmailDiffersFromAPresentOne() {
        assertThat(digester.digest(command("Alice", "Nguyen", "a@b.co")))
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

    private static RegisterCustomerCommand command(String first, String last, String email) {
        return RegisterCustomerCommand.builder().customerId(new CustomerId("90359")).userName(new UserName("alice"))
                .firstName(first).lastName(last).phoneNumber(new PhoneNumber("+84901234567"))
                .email(email == null ? null : new Email(email)).build();
    }

    private static byte[] key(int fill) {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) fill);
        return key;
    }
}
