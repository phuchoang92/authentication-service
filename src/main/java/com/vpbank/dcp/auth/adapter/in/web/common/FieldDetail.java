package com.vpbank.dcp.auth.adapter.in.web.common;

/** A field that failed validation. Never carries the submitted value. */
public record FieldDetail(String field, String message) { }
