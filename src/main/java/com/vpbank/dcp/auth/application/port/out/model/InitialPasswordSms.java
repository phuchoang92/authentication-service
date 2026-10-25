package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.PhoneNumber;
import com.vpbank.dcp.auth.domain.model.RegistrationId;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.util.Objects;
import lombok.Builder;

/**
 * The first-password SMS. {@code messageId} is the registration request id, so Notification
 * can drop a duplicate. The password lives only in this object and is never printed.
 */
@Builder
public record InitialPasswordSms(RegistrationId messageId, CustomerId customerId, PhoneNumber phone,
                                 UserName userName, String password) {
    public InitialPasswordSms {
        Objects.requireNonNull(messageId, "messageId");
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(phone, "phone");
        Objects.requireNonNull(userName, "userName");
        Objects.requireNonNull(password, "password");
    }

    @Override
    public String toString() {
        return "InitialPasswordSms[messageId=" + messageId + ", redacted]";
    }
}
