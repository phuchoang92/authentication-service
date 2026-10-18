package com.vpbank.dcp.infrastructure.adapter.out.mfa;

record MfaCheckRequest(String authOperationId, String contextDigest) { }
