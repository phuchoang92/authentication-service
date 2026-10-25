package com.vpbank.dcp.auth.adapter.in.web.common;

import java.util.List;

/** The error half of {@link ApiEnvelope}: a stable code, a localized message, field details for 400. */
public record ApiError(String code, String message, List<FieldDetail> details) { }
