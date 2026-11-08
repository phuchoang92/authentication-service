package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.output.CommandOutput;
import io.lettuce.core.output.StatusOutput;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.connection.DecoratedRedisConnection;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnection;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Read and compare-and-set on one STRING key, each in a single Valkey command (no Lua, no {@code WATCH}): the
 * server itself compares the stored text before it writes, so a write is one round trip on the shared
 * connection.
 *
 * <ul>
 *     <li>create: {@code SET key text NX PXAT deadline}</li>
 *     <li>replace: {@code SET key text IFEQ expectedText PXAT deadline} (Valkey 8.1)</li>
 *     <li>delete: {@code SET key "" IFEQ expectedText PX 1000} claims the key by turning it into an empty
 *     tombstone, then {@code DEL key} removes it. The claim is the atomic step, so of two racing callers exactly
 *     one wins; a tombstone decodes as "no record" and expires by itself if the DEL never comes. Two commands
 *     instead of Valkey 9.0's {@code DELIFEQ}, because ElastiCache offers 8.1/8.2 by default.</li>
 * </ul>
 *
 * <p>Everything a Valkey 8.1 server has. Spring Data Redis has no typed call for {@code IFEQ}, so the commands go
 * to Lettuce by name. Spring's {@code DataAccessException} leaves this class; the adapter translates it.
 */
@RequiredArgsConstructor
public final class ValkeyRecordCommands {
    private static final String OK = "OK";
    /** The claimed key's text; nothing decodes from it. */
    private static final String TOMBSTONE = "";
    /** How long a claimed key may linger when the DEL after the claim never comes. */
    private static final String TOMBSTONE_MILLIS = "1000";

    @NonNull
    private final StringRedisTemplate stringRedisTemplate;

    public Optional<String> read(@NonNull String key) {
        return Optional.ofNullable(stringRedisTemplate.opsForValue().get(key));
    }

    /** Removes the key whatever it holds. True when this call removed it: of two racing callers one gets true. */
    public boolean delete(@NonNull String key) {
        return Boolean.TRUE.equals(stringRedisTemplate.delete(key));
    }

    /** Writes the record only when its key holds nothing. False: another record is there and stays. */
    public boolean createIfAbsent(@NonNull ValkeyRecord fresh) {
        Object reply = send("SET", statusReply(),
                fresh.key(), fresh.text(), "NX", "PXAT", epochMillis(fresh));
        return OK.equals(reply);
    }

    /** Writes the replacement only while the key still holds exactly the expected text. False: changed or gone. */
    public boolean replaceIfUnchanged(@NonNull ValkeyRecord expected, @NonNull ValkeyRecord replacement) {
        if (!expected.key().equals(replacement.key())) {
            throw new IllegalArgumentException("A record is replaced under its own key");
        }
        Object reply = send("SET", statusReply(),
                replacement.key(), replacement.text(), "IFEQ", expected.text(), "PXAT", epochMillis(replacement));
        return OK.equals(reply);
    }

    /** Removes the key only while it still holds exactly the expected text. Of two racing callers one gets true. */
    public boolean deleteIfUnchanged(@NonNull ValkeyRecord expected) {
        Object claimed = send("SET", statusReply(),
                expected.key(), TOMBSTONE, "IFEQ", expected.text(), "PX", TOMBSTONE_MILLIS);
        if (!OK.equals(claimed)) {
            return false;
        }
        delete(expected.key());
        return true;
    }

    private Object send(String command, CommandOutput<byte[], byte[], ?> reply, String... arguments) {
        byte[][] rawArguments = new byte[arguments.length][];
        for (int i = 0; i < arguments.length; i++) {
            rawArguments[i] = arguments[i].getBytes(StandardCharsets.UTF_8);
        }
        RedisCallback<Object> oneCommand =
                connection -> lettuceConnection(connection).execute(command, reply, rawArguments);
        return stringRedisTemplate.execute(oneCommand, true);
    }

    /** The template hands out its Lettuce connection inside a string-typed decorator. */
    private static LettuceConnection lettuceConnection(RedisConnection connection) {
        RedisConnection undecorated = connection;
        if (connection instanceof DecoratedRedisConnection decorated) {
            undecorated = decorated.getDelegate();
        }
        return (LettuceConnection) undecorated;
    }

    private static StatusOutput<byte[], byte[]> statusReply() {
        return new StatusOutput<>(ByteArrayCodec.INSTANCE);
    }

    private static String epochMillis(ValkeyRecord record) {
        return Long.toString(record.expiresAt().toEpochMilli());
    }
}
