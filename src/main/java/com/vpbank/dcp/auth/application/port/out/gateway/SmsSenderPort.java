package com.vpbank.dcp.auth.application.port.out.gateway;

import com.vpbank.dcp.auth.application.port.out.model.InitialPasswordSms;

/** The Notification service. Throws {@link PartnerUnavailableException} when it cannot answer. */
public interface SmsSenderPort {

    /** True only when Notification accepted responsibility for sending. */
    boolean sendInitialPassword(InitialPasswordSms sms);
}
