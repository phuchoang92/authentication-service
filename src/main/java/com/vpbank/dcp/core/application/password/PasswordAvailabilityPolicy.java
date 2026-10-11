package com.vpbank.dcp.core.application.password;

/** Production remains closed until event interruption, nonce and abuse policies are approved. */
public record PasswordAvailabilityPolicy(boolean integrationActivationEnabled) { }
