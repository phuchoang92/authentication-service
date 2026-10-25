package com.vpbank.dcp.auth.infrastructure.adapter.out.notification;

import com.vpbank.dcp.auth.core.customer.PartnerUnavailableException;
import com.vpbank.dcp.auth.core.customer.SmsSender;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Notification SMS with template INITIAL_PASSWORD. Accepted only when the reply says ACCEPTED
 * for the same message ID. A 4xx is a definite "not accepted"; 5xx or a timeout is unavailable.
 */
public final class HttpSmsSender implements SmsSender {
    private static final String PARTNER = "Notification service";

    private final RestClient client;
    private final String smsPath;
    private final String serviceToken;

    public HttpSmsSender(RestClient client, String smsPath, String serviceToken) {
        this.client = Objects.requireNonNull(client);
        this.smsPath = Objects.requireNonNull(smsPath);
        this.serviceToken = Objects.requireNonNull(serviceToken);
    }

    @Override
    public boolean sendInitialPassword(UUID messageId, String customerId, String phone, String userName,
                                       String password) {
        Map<String, Object> message = Map.of(
                "messageId", messageId.toString(),
                "customerId", customerId,
                "phone", phone,
                "templateCode", "INITIAL_PASSWORD",
                "parameters", Map.of("userName", userName, "initialPassword", password));
        try {
            return client.post().uri(smsPath)
                    .headers(headers -> headers.setBearerAuth(serviceToken))
                    .contentType(MediaType.APPLICATION_JSON).accept(MediaType.APPLICATION_JSON)
                    .body(message)
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        if (status >= 400 && status < 500) {
                            return false;
                        }
                        if (status < 200 || status >= 300) {
                            throw new PartnerUnavailableException(PARTNER);
                        }
                        SmsResponse body = response.bodyTo(SmsResponse.class);
                        return body != null && "ACCEPTED".equals(body.state())
                                && messageId.toString().equals(body.messageId());
                    });
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }

    record SmsResponse(String state, String messageId) { }
}
