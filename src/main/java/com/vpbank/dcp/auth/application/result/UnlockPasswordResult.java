package com.vpbank.dcp.auth.application.result;

public sealed interface UnlockPasswordResult {
    /** Status ACTIVE, count 0, no lockout time — also when nothing was locked. */
    record Unlocked() implements UnlockPasswordResult { }

    record UnknownCustomer() implements UnlockPasswordResult { }

    record Unavailable() implements UnlockPasswordResult { }
}
