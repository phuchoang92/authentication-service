package com.vpbank.dcp.auth.infrastructure.adapter.out.customer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.CustomerProfile;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.net.SocketTimeoutException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class CustomerHttpAdapterTest {
    private final RestClient.Builder builder = RestClient.builder().baseUrl("https://customer.test");
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final CustomerHttpAdapter directory = new CustomerHttpAdapter(builder.build(),
            "/internal/v1/customers/{customerId}/profile", "service-token");

    @Test
    void readsAnEligibleVerifiedProfile() {
        server.expect(requestTo("https://customer.test/internal/v1/customers/90359/profile"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer service-token"))
                .andRespond(withSuccess("""
                        {"customerId":"90359","status":"ELIGIBLE","phone":"+84901234567",
                         "phoneVerified":true,"email":"a@b.c","emailVerified":false}""",
                        MediaType.APPLICATION_JSON));

        assertThat(directory.profile(new CustomerId("90359"))).contains(CustomerProfile.builder()
                .customerId(new CustomerId("90359")).eligible(true).phone("+84901234567").phoneVerified(true)
                .email("a@b.c").emailVerified(false).build());
        server.verify();
    }

    @Test
    void anyOtherStatusIsNotEligibleAndMissingFlagsAreFalse() {
        server.expect(requestTo("https://customer.test/internal/v1/customers/90359/profile"))
                .andRespond(withSuccess("""
                        {"customerId":"90359","status":"BLOCKED","phone":"+84901234567"}""",
                        MediaType.APPLICATION_JSON));

        CustomerProfile profile = directory.profile(new CustomerId("90359")).orElseThrow();
        assertThat(profile.eligible()).isFalse();
        assertThat(profile.phoneVerified()).isFalse();
    }

    @Test
    void notFoundIsAnUnknownCustomer() {
        server.expect(requestTo("https://customer.test/internal/v1/customers/90359/profile"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        assertThat(directory.profile(new CustomerId("90359"))).isEmpty();
    }

    @Test
    void anErrorATimeoutOrAnotherCustomersProfileIsUnavailable() {
        server.expect(requestTo("https://customer.test/internal/v1/customers/90359/profile"))
                .andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));
        assertThatThrownBy(() -> directory.profile(new CustomerId("90359"))).isInstanceOf(PartnerUnavailableException.class);

        server.reset();
        server.expect(requestTo("https://customer.test/internal/v1/customers/90359/profile"))
                .andRespond(withException(new SocketTimeoutException("slow")));
        assertThatThrownBy(() -> directory.profile(new CustomerId("90359"))).isInstanceOf(PartnerUnavailableException.class);

        server.reset();
        server.expect(requestTo("https://customer.test/internal/v1/customers/90359/profile"))
                .andRespond(withSuccess("{\"customerId\":\"11111\",\"status\":\"ELIGIBLE\"}",
                        MediaType.APPLICATION_JSON));
        assertThatThrownBy(() -> directory.profile(new CustomerId("90359"))).isInstanceOf(PartnerUnavailableException.class);
    }
}
