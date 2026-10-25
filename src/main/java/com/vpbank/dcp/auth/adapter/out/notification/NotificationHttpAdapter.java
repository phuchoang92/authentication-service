package com.vpbank.dcp.auth.adapter.out.notification;

import com.vpbank.dcp.auth.adapter.out.notification.dto.SmsResponse;
import com.vpbank.dcp.auth.adapter.out.notification.mapper.SmsMapper;
import com.vpbank.dcp.auth.application.port.out.InitialPasswordSms;
import com.vpbank.dcp.auth.application.port.out.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.SmsSenderPort;
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

    @NonNull private final RestClient client;
    @NonNull private final String smsPath;
    @NonNull private final String serviceToken;

    @Override
    public boolean sendInitialPassword(InitialPasswordSms sms) {
        try {
            return client.post().uri(smsPath)
                    .headers(headers -> headers.setBearerAuth(serviceToken))
                    .contentType(MediaType.APPLICATION_JSON).accept(MediaType.APPLICATION_JSON)
                    .body(SmsMapper.toRequest(sms))
                    .exchange((request, response) -> {
                        int status = response.getStatusCode().value();
                        if (status >= 400 && status < 500) {
                            return false;
                        }
                        if (status < 200 || status >= 300) {
                            throw new PartnerUnavailableException(PARTNER);
                        }
                        return SmsMapper.accepted(response.bodyTo(SmsResponse.class), sms);
                    });
        } catch (RestClientException failure) {
            throw new PartnerUnavailableException(PARTNER, failure);
        }
    }
}
