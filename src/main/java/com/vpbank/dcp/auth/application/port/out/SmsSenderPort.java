package com.vpbank.dcp.auth.application.port.out;

/** The Notification service. Throws {@link PartnerUnavailableException} when it cannot answer. */
public interface SmsSenderPort {

    /** True only when Notification accepted responsibility for sending. */
    boolean sendInitialPassword(InitialPasswordSms sms);
}
