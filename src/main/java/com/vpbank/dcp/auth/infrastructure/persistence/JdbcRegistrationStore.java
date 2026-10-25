package com.vpbank.dcp.auth.infrastructure.persistence;

import com.vpbank.dcp.auth.core.customer.Registration;
import com.vpbank.dcp.auth.core.customer.RegistrationState;
import com.vpbank.dcp.auth.core.customer.RegistrationStore;
import com.vpbank.dcp.auth.core.customer.RegistrationStoreUnavailableException;
import com.vpbank.dcp.auth.core.customer.RequestDigest;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.ByteBuffer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Registrations in CUSTOMER_AUTHENTICATION_REGISTRATION, plus the identity row written when one
 * completes. The database only stops races (one open request per customer and per username,
 * one identity per username and Keycloak subject); every step rule is checked here in SQL.
 * Times are stored as UTC, whatever the server's time zone.
 */
public final class JdbcRegistrationStore implements RegistrationStore {
    private static final String COLUMNS = """
            REQUEST_ID, CUSTOMER_ID, USERNAME, REQUEST_DIGEST, STATE, IDENTITY_ISSUER,
            IDENTITY_SUBJECT, EXPIRES_AT, VERSION""";

    private final JdbcClient jdbc;
    private final TransactionTemplate transactions;

    public JdbcRegistrationStore(JdbcClient jdbc, TransactionTemplate transactions) {
        this.jdbc = Objects.requireNonNull(jdbc);
        this.transactions = Objects.requireNonNull(transactions);
    }

    @Override
    public ReserveResult reserve(UUID requestId, String customerId, String userName,
                                 RequestDigest requestDigest, Instant expiresAt, Instant now) {
        try {
            jdbc.sql("""
                    INSERT INTO CUSTOMER_AUTHENTICATION_REGISTRATION
                        (REQUEST_ID, CUSTOMER_ID, USERNAME, STATE, REQUEST_DIGEST, EXPIRES_AT,
                         VERSION, CREATED_AT, UPDATED_AT)
                    VALUES (:id, :customer, :userName, 'RESERVED', :digest, :expires, 0, :now, :now)
                    """)
                    .param("id", bytes(requestId)).param("customer", customerId)
                    .param("userName", userName).param("digest", requestDigest.bytes())
                    .param("expires", utc(expiresAt)).param("now", utc(now))
                    .update();
            return new ReserveResult.Reserved(new Registration(requestId, customerId, userName,
                    requestDigest, RegistrationState.RESERVED, null, null, expiresAt, 0));
        } catch (DuplicateKeyException taken) {
            // Either the customer or the username already has an open request.
            try {
                return findOpen(customerId)
                        .<ReserveResult>map(ReserveResult.CustomerHasOpen::new)
                        .orElseGet(ReserveResult.UserNameTaken::new);
            } catch (DataAccessException failure) {
                throw new RegistrationStoreUnavailableException(failure);
            }
        } catch (DataAccessException failure) {
            throw new RegistrationStoreUnavailableException(failure);
        }
    }

    @Override
    public Optional<Registration> findLatest(String customerId) {
        try {
            return jdbc.sql("SELECT " + COLUMNS + """
                     FROM CUSTOMER_AUTHENTICATION_REGISTRATION
                    WHERE CUSTOMER_ID = :customer
                    ORDER BY CREATED_AT DESC, REQUEST_ID DESC
                    LIMIT 1""")
                    .param("customer", customerId)
                    .query(JdbcRegistrationStore::registration).optional();
        } catch (DataAccessException failure) {
            throw new RegistrationStoreUnavailableException(failure);
        }
    }

    @Override
    public boolean markUserCreated(UUID requestId, long version, String identityIssuer,
                                   String identitySubject, Instant now) {
        Objects.requireNonNull(identityIssuer, "identityIssuer");
        Objects.requireNonNull(identitySubject, "identitySubject");
        return update("""
                UPDATE CUSTOMER_AUTHENTICATION_REGISTRATION
                   SET STATE = 'USER_CREATED', IDENTITY_ISSUER = :issuer, IDENTITY_SUBJECT = :subject,
                       VERSION = VERSION + 1, UPDATED_AT = :now
                 WHERE REQUEST_ID = :id AND VERSION = :version AND STATE = 'RESERVED'""",
                requestId, version, now, identityIssuer, identitySubject);
    }

    @Override
    public boolean markSmsAccepted(UUID requestId, long version, Instant now) {
        return update("""
                UPDATE CUSTOMER_AUTHENTICATION_REGISTRATION
                   SET STATE = 'SMS_ACCEPTED', VERSION = VERSION + 1, UPDATED_AT = :now
                 WHERE REQUEST_ID = :id AND VERSION = :version AND STATE = 'USER_CREATED'""",
                requestId, version, now, null, null);
    }

    @Override
    public boolean markFailed(UUID requestId, long version, Instant now) {
        return update("""
                UPDATE CUSTOMER_AUTHENTICATION_REGISTRATION
                   SET STATE = 'FAILED', VERSION = VERSION + 1, UPDATED_AT = :now
                 WHERE REQUEST_ID = :id AND VERSION = :version
                   AND STATE IN ('RESERVED', 'USER_CREATED', 'SMS_ACCEPTED')""",
                requestId, version, now, null, null);
    }

    @Override
    public CompleteResult complete(UUID requestId, long version, Instant now) {
        try {
            return transactions.execute(status -> {
                Optional<Registration> locked = jdbc.sql("SELECT " + COLUMNS + """
                         FROM CUSTOMER_AUTHENTICATION_REGISTRATION
                        WHERE REQUEST_ID = :id AND VERSION = :version AND STATE = 'SMS_ACCEPTED'
                        FOR UPDATE""")
                        .param("id", bytes(requestId)).param("version", version)
                        .query(JdbcRegistrationStore::registration).optional();
                if (locked.isEmpty()) {
                    return CompleteResult.STALE;
                }
                Registration registration = locked.get();
                try {
                    jdbc.sql("""
                            INSERT INTO CUSTOMER_AUTHENTICATION
                                (CUSTOMER_ID, USER_NAME, IDENTITY_ISSUER, IDENTITY_SUBJECT, STATUS,
                                 VERSION, CREATED_AT, UPDATED_AT)
                            VALUES (:customer, :userName, :issuer, :subject, 'ACTIVE', 0, :now, :now)
                            """)
                            .param("customer", registration.customerId())
                            .param("userName", registration.userName())
                            .param("issuer", registration.identityIssuer())
                            .param("subject", registration.identitySubject())
                            .param("now", utc(now))
                            .update();
                } catch (DuplicateKeyException taken) {
                    status.setRollbackOnly();
                    return CompleteResult.IDENTITY_TAKEN;
                }
                jdbc.sql("""
                        UPDATE CUSTOMER_AUTHENTICATION_REGISTRATION
                           SET STATE = 'READY', VERSION = VERSION + 1, UPDATED_AT = :now
                         WHERE REQUEST_ID = :id""")
                        .param("id", bytes(requestId)).param("now", utc(now))
                        .update();
                return CompleteResult.COMPLETED;
            });
        } catch (DataAccessException failure) {
            throw new RegistrationStoreUnavailableException(failure);
        }
    }

    private Optional<Registration> findOpen(String customerId) {
        return jdbc.sql("SELECT " + COLUMNS + """
                 FROM CUSTOMER_AUTHENTICATION_REGISTRATION
                WHERE CUSTOMER_ID = :customer AND OPEN_SLOT = 1""")
                .param("customer", customerId)
                .query(JdbcRegistrationStore::registration).optional();
    }

    private boolean update(String sql, UUID requestId, long version, Instant now,
                           String issuer, String subject) {
        try {
            var statement = jdbc.sql(sql)
                    .param("id", bytes(requestId)).param("version", version).param("now", utc(now));
            if (issuer != null) {
                statement = statement.param("issuer", issuer).param("subject", subject);
            }
            return statement.update() == 1;
        } catch (DataAccessException failure) {
            throw new RegistrationStoreUnavailableException(failure);
        }
    }

    private static Registration registration(ResultSet row, int rowNumber) throws SQLException {
        return new Registration(uuid(row.getBytes("REQUEST_ID")), row.getString("CUSTOMER_ID"),
                row.getString("USERNAME"), new RequestDigest(row.getBytes("REQUEST_DIGEST")),
                RegistrationState.valueOf(row.getString("STATE")), row.getString("IDENTITY_ISSUER"),
                row.getString("IDENTITY_SUBJECT"),
                row.getObject("EXPIRES_AT", LocalDateTime.class).toInstant(ZoneOffset.UTC),
                row.getLong("VERSION"));
    }

    private static LocalDateTime utc(Instant instant) {
        return LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    static byte[] bytes(UUID id) {
        return ByteBuffer.allocate(16).putLong(id.getMostSignificantBits())
                .putLong(id.getLeastSignificantBits()).array();
    }

    static UUID uuid(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        return new UUID(buffer.getLong(), buffer.getLong());
    }
}
