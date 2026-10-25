package com.vpbank.dcp.auth.core.customer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class InitialPasswordGeneratorTest {
    private final InitialPasswordGenerator generator = new InitialPasswordGenerator(new SecureRandom(), 12);

    @RepeatedTest(50)
    void hasTheLengthAndOneOfEachKindWithoutLookAlikes() {
        String password = generator.next();

        assertThat(password).hasSize(12).matches(".*[A-Z].*").matches(".*[a-z].*").matches(".*[0-9].*")
                .doesNotContainAnyWhitespaces().matches("[^0O1lI]*");
    }

    @Test
    void lengthOutsideEightToSixtyFourIsRejected() {
        assertThatThrownBy(() -> new InitialPasswordGenerator(new SecureRandom(), 7))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new InitialPasswordGenerator(new SecureRandom(), 65))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
