package com.vpbank.dcp.auth.domain.model;

/** PASSWORD_STATUS of an identity (phase 2). LOCKED is temporary and carries a lockout time; PERMANENTLY_LOCKED needs the bank. */
public enum PasswordStatus {
    ACTIVE,
    LOCKED,
    PERMANENTLY_LOCKED
}
