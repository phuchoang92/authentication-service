package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Frozen key vectors (RK09/RK12): a Java refactor must not move a used-assertion ID to another key. */
class UsedAssertionKeysTest {
    private static final String DIGEST_OF_JTI_1 = "WWTaBVrjHPjrcjDhkKUEiZxvYPB_nxzTyt6fvyJujCg";

    @Test
    void eachKindOfAssertionHasItsOwnPrefixOverTheSameDigest() {
        assertThat(new BffAssertionKeys().forAssertionId("jti-1"))
                .isEqualTo("bff-assertion:used:v1:" + DIGEST_OF_JTI_1);
        assertThat(new ServiceClientAssertionKeys().forAssertionId("jti-1"))
                .isEqualTo("service-client-assertion:used:v1:" + DIGEST_OF_JTI_1);
    }

    @Test
    void theIdItselfNeverAppearsAndTheKeyHasAFixedShape() {
        String key = new ServiceClientAssertionKeys().forAssertionId("a:b/c" + "x".repeat(120));
        assertThat(key).startsWith("service-client-assertion:used:v1:").doesNotContain("a:b/c")
                .hasSize("service-client-assertion:used:v1:".length() + 43);
        assertThat(new ServiceClientAssertionKeys().forAssertionId("jti-2")).isNotEqualTo(
                new ServiceClientAssertionKeys().forAssertionId("jti-1"));
    }
}
