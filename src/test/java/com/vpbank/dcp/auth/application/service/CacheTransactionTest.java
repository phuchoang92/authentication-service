package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** The envelope knows its address, deadline and version; it never looks inside the payload. */
class CacheTransactionTest {
    private static final Instant NOW = Instant.parse("2026-11-04T10:00:00Z");
    private static final TransactionKind<String> NOTES = new TransactionKind<>("notes", String.class);

    @Test
    void opensAtVersionZeroAndEachChangeIsOneVersionLaterWithoutTouchingTheRest() {
        CacheTransaction<String> opened = NOTES.open("abc", NOW.plusSeconds(60), "first");

        assertThat(opened.version()).isZero();
        assertThat(opened.isOpen(NOW)).isTrue();
        assertThat(opened.isOpen(NOW.plusSeconds(60))).isFalse();

        CacheTransaction<String> changed = opened.next("second").next("third");
        assertThat(changed.payload()).isEqualTo("third");
        assertThat(changed.version()).isEqualTo(2);
        assertThat(changed.id()).isEqualTo("abc");
        assertThat(changed.expiresAt()).isEqualTo(opened.expiresAt());
        assertThat(changed.kind()).isEqualTo(NOTES);
    }

    @Test
    void refusesABadIdANegativeVersionOrAPayloadOfAnotherType() {
        assertThatThrownBy(() -> NOTES.open("", NOW, "p")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> NOTES.open("a b", NOW, "p")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> NOTES.open("x".repeat(201), NOW, "p")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CacheTransaction<>(NOTES, "abc", NOW, -1, "p")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> NOTES.open("abc", NOW, null)).isInstanceOf(NullPointerException.class);
        TransactionKind<Object> loose = new TransactionKind<>("loose", Object.class);
        assertThat(loose.open("abc", NOW, 42).payload()).isEqualTo(42);
    }

    @Test
    void printsTheAddressNeverThePayload() {
        assertThat(NOTES.open("abc", NOW, "a secret").toString())
                .contains("notes").contains("abc").doesNotContain("secret");
    }
}
