package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import com.vpbank.dcp.auth.infrastructure.config.RestConfiguration;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/** The gate of the service-token route: one Bearer client assertion, genuine, used once; the JWKS route is open. */
class ServiceClientAssertionFilterTest {
    private static final String ISSUE = ServiceClientAssertionFilter.ISSUE_PATH;

    private final Map<String, Instant> usedAssertionIds = new HashMap<>();
    private boolean replayStoreDown;
    private final AssertionReplayGuard replayGuard = (assertionId, rememberUntil) -> {
        if (replayStoreDown) {
            throw new RepositoryUnavailableException(new IllegalStateException("Valkey down"));
        }
        return usedAssertionIds.putIfAbsent(assertionId, rememberUntil) == null;
    };
    private final ServiceClientAssertionFilter filter = new ServiceClientAssertionFilter(
            new ServiceClientAssertionVerifier(
                    Map.of(new ServiceId(TestServiceClientAssertions.SERVICE_ID), TestServiceClientAssertions.publicKey()),
                    Clock.systemUTC()),
            replayGuard,
            new ErrorMessages(RestConfiguration.errorMessageSource()),
            RestConfiguration.acceptHeaderLocaleResolver());

    @Test
    void aGenuineAssertionIsUsedOnceAndLeavesTheCallerForTheController() throws Exception {
        String assertion = TestServiceClientAssertions.assertion();

        MockHttpServletRequest request = request("POST", ISSUE, "Bearer " + assertion);
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isNotNull();
        VerifiedServiceClient callingService =
                (VerifiedServiceClient) request.getAttribute(ServiceClientAssertionFilter.CALLING_SERVICE_ATTRIBUTE);
        assertThat(callingService.serviceId()).isEqualTo(new ServiceId("onboarding-service"));
        assertThat(usedAssertionIds).hasSize(1);
        // The ID is remembered at least until the assertion's expiry plus the accepted skew.
        assertThat(usedAssertionIds.values().iterator().next()).isAfter(Instant.now().plusSeconds(30));

        MockHttpServletResponse replayed = run(request("POST", ISSUE, "Bearer " + assertion));
        assertThat(replayed.getStatus()).isEqualTo(401);
        assertThat(replayed.getContentAsString()).contains("\"code\":\"REQUEST_REJECTED\"");
    }

    @Test
    void noAssertionTwoHeadersAnotherSchemeOrABffAssertionAreRejected() throws Exception {
        assertRejected(request("POST", ISSUE, null));
        MockHttpServletRequest twoHeaders = request("POST", ISSUE, "Bearer " + TestServiceClientAssertions.assertion());
        twoHeaders.addHeader("Authorization", "Bearer " + TestServiceClientAssertions.assertion());
        assertRejected(twoHeaders);
        assertRejected(request("POST", ISSUE, "DPoP " + TestServiceClientAssertions.assertion()));
        assertRejected(request("POST", ISSUE, "Bearer " + TestBffAssertions.assertion(
                "00000000-0000-4000-8000-000000000003", "90359", "MOBILE", "tablet-2", "ACTIVE")));
        assertThat(usedAssertionIds).isEmpty();
    }

    @Test
    void aReplayStoreThatCannotAnswerAdmitsNobody() throws Exception {
        replayStoreDown = true;

        MockHttpServletResponse response = run(request("POST", ISSUE, "Bearer " + TestServiceClientAssertions.assertion()));

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getContentAsString()).contains("\"code\":\"TEMPORARILY_UNAVAILABLE\"");
    }

    @Test
    void onlyThePostToTheIssueRouteIsGated() throws Exception {
        for (MockHttpServletRequest open : new MockHttpServletRequest[] {
                request("GET", ISSUE + "/jwks", null),
                request("GET", ISSUE, null),
                request("POST", "/internal/v1/sessions/extend", null),
                request("POST", "/api/v1/trusted-device/init", null)}) {
            MockFilterChain chain = new MockFilterChain();
            filter.doFilter(open, new MockHttpServletResponse(), chain);
            assertThat(chain.getRequest()).as(open.getRequestURI()).isNotNull();
            assertThat(open.getAttribute(ServiceClientAssertionFilter.CALLING_SERVICE_ATTRIBUTE)).isNull();
        }
    }

    private void assertRejected(MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = run(request);
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("\"code\":\"REQUEST_REJECTED\"");
        assertThat(request.getAttribute(ServiceClientAssertionFilter.CALLING_SERVICE_ATTRIBUTE)).isNull();
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

    private static MockHttpServletRequest request(String method, String path, String authorization) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        if (authorization != null) {
            request.addHeader("Authorization", authorization);
        }
        return request;
    }
}
