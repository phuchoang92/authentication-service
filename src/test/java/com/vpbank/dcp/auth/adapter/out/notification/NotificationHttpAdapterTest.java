package com.vpbank.dcp.auth.adapter.out.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vpbank.dcp.auth.application.port.out.InitialPasswordSms;
import com.vpbank.dcp.auth.application.port.out.PartnerUnavailableException;
import com.vpbank.dcp.auth.domain.model.RegistrationId;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.PhoneNumber;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class NotificationHttpAdapterTest {
    private static final UUID MESSAGE = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private final RestClient.Builder builder = RestClient.builder().baseUrl("https://notify.test");
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final NotificationHttpAdapter sender = new NotificationHttpAdapter(builder.build(), "/internal/v1/notifications/sms",
            "service-token");

    @Test
    void sendsTheInitialPasswordTemplateAndAcceptsOnlyTheSameMessage() {
        server.expect(requestTo("https://notify.test/internal/v1/notifications/sms"))
                .andExpect(header("Authorization", "Bearer service-token"))
                .andExpect(jsonPath("$.messageId").value(MESSAGE.toString()))
                .andExpect(jsonPath("$.templateCode").value("INITIAL_PASSWORD"))
                .andExpect(jsonPath("$.phone").value("+84901234567"))
                .andExpect(jsonPath("$.parameters.userName").value("alice"))
                .andExpect(jsonPath("$.parameters.initialPassword").value("Secret123"))
                .andRespond(withSuccess("{\"state\":\"ACCEPTED\",\"messageId\":\"" + MESSAGE + "\"}",
                        MediaType.APPLICATION_JSON));

        assertThat(sender.sendInitialPassword(sms("Secret123"))).isTrue();
        server.verify();
    }

    @Test
    void anotherMessageIdOrStateOrAClientErrorIsNotAccepted() {
        server.expect(requestTo("https://notify.test/internal/v1/notifications/sms"))
                .andRespond(withSuccess("{\"state\":\"ACCEPTED\",\"messageId\":\"other\"}",
                        MediaType.APPLICATION_JSON));
        assertThat(sender.sendInitialPassword(sms("x"))).isFalse();

        server.reset();
        server.expect(requestTo("https://notify.test/internal/v1/notifications/sms"))
                .andRespond(withStatus(HttpStatus.BAD_REQUEST));
        assertThat(sender.sendInitialPassword(sms("x"))).isFalse();
    }

    @Test
    void aServerErrorIsUnavailable() {
        server.expect(requestTo("https://notify.test/internal/v1/notifications/sms"))
                .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));

        assertThatThrownBy(() -> sender.sendInitialPassword(sms("x")))
                .isInstanceOf(PartnerUnavailableException.class);
    }

    private static InitialPasswordSms sms(String password) {
        return InitialPasswordSms.builder().messageId(new RegistrationId(MESSAGE)).customerId(new CustomerId("90359"))
                .phone(new PhoneNumber("+84901234567")).userName(new UserName("alice")).password(password).build();
    }
}
