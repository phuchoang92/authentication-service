package com.vpbank.dcp.auth.infrastructure.adapter.out.notification.mapper;

import com.vpbank.dcp.auth.infrastructure.adapter.out.notification.dto.SmsRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.out.notification.dto.SmsResponse;
import com.vpbank.dcp.auth.application.port.out.model.InitialPasswordSms;

import java.util.Map;

/** Port value types ↔ Notification payloads. */
public final class SmsMapper {
    public static final String INITIAL_PASSWORD_TEMPLATE = "INITIAL_PASSWORD";
    private static final String ACCEPTED = "ACCEPTED";

    private SmsMapper() {
    }

    public static SmsRequest toRequest(InitialPasswordSms sms) {
        return SmsRequest.builder()
                .messageId(sms.messageId().toString())
                .customerId(sms.customerId().value())
                .phone(sms.phone().value())
                .templateCode(INITIAL_PASSWORD_TEMPLATE)
                .parameters(Map.of("userName", sms.userName().value(), "initialPassword", sms.password()))
                .build();
    }

    /** Accepted only for the same message: a reply about another message proves nothing. */
    public static boolean accepted(SmsResponse body, InitialPasswordSms sms) {
        return body != null && ACCEPTED.equals(body.state()) && sms.messageId().toString().equals(body.messageId());
    }
}
