package com.vpbank.dcp.auth.adapter.out.customer.dto;

/** Customer service {@code GET …/profile} body; flags may be absent and then count as false. */
public record CustomerProfileDto(String customerId, String status, String phone, Boolean phoneVerified,
                                 String email, Boolean emailVerified) { }
