package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.infrastructure.config.RestConfiguration;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/** The gate of the trusted-device routes: one Bearer assertion, genuine, used once; nothing else is admitted. */
class BffAssertionFilterTest {
    private static final String INIT = "/api/v1/trusted-device/init";

    private final Map<String, Instant> usedAssertionIds = new HashMap<>();
    private boolean replayStoreDown;
    private final AssertionReplayGuard replayGuard = (assertionId, rememberUntil) -> {
        if (replayStoreDown) {
            throw new RepositoryUnavailableException(new IllegalStateException("Valkey down"));
        }
        return usedAssertionIds.putIfAbsent(assertionId, rememberUntil) == null;
    };
    private final BffAssertionFilter filter = new BffAssertionFilter(
            new BffAssertionVerifier(TestBffAssertions.publicKey(), TestBffAssertions.ISSUER, Clock.systemUTC()),
            replayGuard,
            new ErrorMessages(RestConfiguration.errorMessageSource()),
            RestConfiguration.acceptHeaderLocaleResolver());

    @Test
    void aGenuineAssertionIsUsedOnceAndLeavesTheAdmittedSessionForTheController() throws Exception {
        String assertion = restrictedTablet();

        MockHttpServletRequest request = request(INIT, "Bearer " + assertion);
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        BffAdmission admission = (BffAdmission) request.getAttribute(BffAssertionFilter.ADMISSION_ATTRIBUTE);
        assertThat(admission.admittedSession().status()).isEqualTo(SessionStatus.NEED_TRUSTED_DEVICE);
        assertThat(admission.admittedSession().deviceId().value()).isEqualTo("tablet-2");
        assertThat(usedAssertionIds).hasSize(1);
        // The ID is remembered at least until the assertion's expiry plus the accepted skew.
        assertThat(usedAssertionIds.values().iterator().next()).isAfter(Instant.now().plusSeconds(30));

        MockHttpServletResponse replayed = run(request(INIT, "Bearer " + assertion));
        assertThat(replayed.getStatus()).isEqualTo(401);
        assertThat(replayed.getContentAsString()).contains("\"code\":\"REQUEST_REJECTED\"");
    }

    @Test
    void noAssertionTwoHeadersAnotherSchemeOrTheAppTokenAreRejected() throws Exception {
        assertRejected(request(INIT, null));
        MockHttpServletRequest twoHeaders = request(INIT, "Bearer " + restrictedTablet());
        twoHeaders.addHeader("Authorization", "Bearer " + restrictedTablet());
        assertRejected(twoHeaders);
        assertRejected(request(INIT, "DPoP " + restrictedTablet()));
        assertRejected(request(INIT, "Bearer s1:auth:session:MOBILE:00000000-0000-4000-8000-000000000003:" + "C".repeat(43)));
        assertThat(usedAssertionIds).isEmpty();
    }

    @Test
    void aReplayStoreThatCannotAnswerAdmitsNobody() throws Exception {
        replayStoreDown = true;

        MockHttpServletResponse response = run(request(INIT, "Bearer " + restrictedTablet()));

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getContentAsString()).contains("\"code\":\"TEMPORARILY_UNAVAILABLE\"");
    }

    @Test
    void onlyTheTrustedDeviceRoutesAreGatedAndTheSessionFilterLeavesThemAlone() throws Exception {
        MockHttpServletRequest devices = request("/api/v1/devices", null);
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(devices, new MockHttpServletResponse(), chain);
        assertThat(chain.getRequest()).isNotNull(); // not this filter's route

        SessionFilter sessionFilter = new SessionFilter(new ErrorMessages(RestConfiguration.errorMessageSource()),
                RestConfiguration.acceptHeaderLocaleResolver());
        MockHttpServletRequest init = request(INIT, "Bearer " + restrictedTablet());
        MockFilterChain sessionChain = new MockFilterChain();
        sessionFilter.doFilter(init, new MockHttpServletResponse(), sessionChain);
        assertThat(sessionChain.getRequest()).isNotNull();
        assertThat(init.getAttribute(SessionFilter.TOKEN_ATTRIBUTE)).isNull();
    }

    private void assertRejected(MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = run(request);
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("\"code\":\"REQUEST_REJECTED\"");
        assertThat(request.getAttribute(BffAssertionFilter.ADMISSION_ATTRIBUTE)).isNull();
    }

    private MockHttpServletResponse run(MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, response, chain);
        if (response.getStatus() != 200) {
            assertThat(chain.getRequest()).isNull(); // a refused request never reaches the controller
        }
        return response;
    }

    private static MockHttpServletRequest request(String path, String authorization) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        if (authorization != null) {
            request.addHeader("Authorization", authorization);
        }
        return request;
    }

    private static String restrictedTablet() {
        return TestBffAssertions.assertion("00000000-0000-4000-8000-000000000003", "90359", "MOBILE", "tablet-2",
                "NEED_TRUSTED_DEVICE");
    }
}
