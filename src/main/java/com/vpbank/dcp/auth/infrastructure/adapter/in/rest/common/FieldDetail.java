package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

/** A field that failed validation. Never carries the submitted value. */
public record FieldDetail(String field, String message) { }
