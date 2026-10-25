package com.vpbank.dcp.auth.infrastructure.adapter.out.notification.dto;

import java.util.Map;
import lombok.Builder;

/** Notification {@code POST …/sms} body. Parameters carry the password: never printed. */
@Builder
public record SmsRequest(String messageId, String customerId, String phone, String templateCode,
                         Map<String, String> parameters) {
    @Override
    public String toString() {
        return "SmsRequest[messageId=" + messageId + ", templateCode=" + templateCode + ", redacted]";
    }
}
