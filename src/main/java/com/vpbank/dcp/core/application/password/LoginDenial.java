package com.vpbank.dcp.core.application.password;

/**
 * Every terminal outcome of the password login flow, declared once and mapped once in
 * {@link PasswordLoginService}. Steps return this instead of each re-declaring their own
 * {@code Rejected}/{@code Unavailable} pair, which previously lost information at every hop.
 *
 * <p>There is deliberately no {@code CONFLICT} constant yet. {@code PasswordLoginResult.Conflict}
 * is mapped to 409 STATE_CONFLICT by the web layer and is published in the API contract, but no
 * producer exists: owner conflict and not-claimable currently answer REJECTED. Adding the constant
 * here without a producer would recreate the dead branch this refactor removed. Wiring it changes
 * externally visible behaviour and needs its own decision.
 */
public enum LoginDenial {
    REJECTED,
    UNAVAILABLE
}
