package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class TransactionKeysTest {
    private static final TransactionKind<String> KIND = new TransactionKind<>("enrollment", String.class);

    @Test
    void theKeyIsNamespacePurposeAndIdInClear() {
        assertThat(new TransactionKeys().forTransaction(KIND, "MOBILE:90359:tablet-2"))
                .isEqualTo("tx:v2:enrollment:MOBILE:90359:tablet-2");
        assertThat(new TransactionKeys("auth:tx:v2:").forTransaction(KIND, "abc")).isEqualTo("auth:tx:v2:enrollment:abc");
        CacheTransaction<String> transaction = KIND.open("abc", Instant.now(), "payload");
        assertThat(new TransactionKeys().forTransaction(transaction)).isEqualTo("tx:v2:enrollment:abc");
    }

    @Test
    void purposeAndIdEachChangeTheKeyAndANamespaceEndsWithAColon() {
        String enrollment = new TransactionKeys().forTransaction(KIND, "abc");
        assertThat(new TransactionKeys().forTransaction(new TransactionKind<>("credential", String.class), "abc"))
                .isNotEqualTo(enrollment);
        assertThat(new TransactionKeys().forTransaction(KIND, "abd")).isNotEqualTo(enrollment);
        assertThatThrownBy(() -> new TransactionKeys("tx")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TransactionKind<>("Enrollment", String.class)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> KIND.open("has space", Instant.now(), "p"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
