package com.vpbank.dcp.infrastructure.adapter.in.web.password.dto;

/** The implemented password outcomes; each preserves its own public JSON shape. */
public sealed interface PasswordLoginResponse permits PasswordLoginActiveResponse,
        PasswordLoginProcessingResponse, PasswordLoginErrorResponse {
}
