package com.vpbank.dcp.auth.infrastructure.adapter.out.notification;

import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.SmsSenderPort;
import com.vpbank.dcp.auth.application.port.out.model.InitialPasswordSms;
import com.vpbank.dcp.auth.infrastructure.adapter.out.notification.dto.SmsRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.out.notification.dto.SmsResponse;
import com.vpbank.dcp.auth.infrastructure.adapter.out.notification.mapper.SmsMapper;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Notification SMS with template INITIAL_PASSWORD. Accepted only when the reply says ACCEPTED
 * for the same message ID. A 4xx is a definite "not accepted"; 5xx or a timeout is unavailable.
 */
@RequiredArgsConstructor
public final class NotificationHttpAdapter implements SmsSenderPort {
    private static final String PARTNER = "Notification service";

    @NonNull private final RestClient restClient;
    @NonNull private final String smsPath;
    @NonNull private final String serviceToken;

    @Override
    public boolean sendInitialPassword(InitialPasswordSms initialPasswordSms) {
        SmsRequest smsRequest = SmsMapper.toRequest(initialPasswordSms);
        try {
            return restClient.post()
                    .uri(smsPath)
                    .headers(headers -> headers.setBearerAuth(serviceToken))
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(smsRequest)
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        boolean clientError = status >= 400 && status < 500;
                        if (clientError) {
                            return false;
                        }
                        boolean success = status >= 200 && status < 300;
                        if (!success) {
                            throw new PartnerUnavailableException(PARTNER);
                        }

                        SmsResponse smsResponse = response.bodyTo(SmsResponse.class);
                        return SmsMapper.accepted(smsResponse, initialPasswordSms);
                    });
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }
}
