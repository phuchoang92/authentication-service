package com.vpbank.dcp.auth.adapter.out.notification.dto;

/** Notification reply: {@code state} is ACCEPTED when it took responsibility for the message. */
public record SmsResponse(String state, String messageId) { }
