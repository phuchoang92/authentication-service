package com.vpbank.dcp.infrastructure.adapter.in.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import tools.jackson.databind.json.JsonMapper;

class WorkloadIdentityFilterTest {

    private final WorkloadIdentityFilter filter = new WorkloadIdentityFilter(
            Set.of("spiffe://bank.test/mobile-bff"), new JsonMapper());

    @Test
    void exactUriSanOnSecureChannelIsAccepted() throws Exception {
        var request = secureRequestWithSan(6, "spiffe://bank.test/mobile-bff");
        var response = new MockHttpServletResponse();
        var chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isSameAs(request);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void missingOrWrongSanAndInsecureTransportAreRejected() throws Exception {
        var wrong = secureRequestWithSan(2, "spiffe://bank.test/mobile-bff");
        var response = new MockHttpServletResponse();
        filter.doFilter(wrong, response, new MockFilterChain());
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).doesNotContain("spiffe://");

        var insecure = secureRequestWithSan(6, "spiffe://bank.test/mobile-bff");
        insecure.setSecure(false);
        var otherResponse = new MockHttpServletResponse();
        filter.doFilter(insecure, otherResponse, new MockFilterChain());
        assertThat(otherResponse.getStatus()).isEqualTo(403);
    }

    @Test
    void missingAllowlistFailsStartup() {
        assertThatThrownBy(() -> new WorkloadIdentityFilter(Set.of(), new JsonMapper()))
                .isInstanceOf(InvalidWorkloadIdentityConfigurationException.class);
    }

    private MockHttpServletRequest secureRequestWithSan(int type, String name) throws Exception {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectAlternativeNames()).thenReturn(List.of(List.of(type, name)));
        var request = new MockHttpServletRequest("POST", "/api/v1/authentications");
        request.setSecure(true);
        request.setAttribute("jakarta.servlet.request.X509Certificate",
                new X509Certificate[] {certificate});
        return request;
    }
}
