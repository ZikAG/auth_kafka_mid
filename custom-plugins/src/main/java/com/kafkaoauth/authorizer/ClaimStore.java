package com.kafkaoauth.authorizer;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe static store for JWT claims, shared between the validator callback handler
 * and the authorizer.
 *
 * <p>When {@link com.kafkaoauth.OAuthBearerValidatorCallbackHandler} successfully validates
 * a client token it calls {@link #put(String, Map)} to make the parsed claims available
 * to {@link CustomKafkaAuthorizer} during the authorization phase.
 *
 * <p>Keys are the Kafka principal names (the value of the {@code sub} claim by default).
 * Values are immutable snapshots of the JWT claims map.
 *
 * <p>Callers should call {@link #remove(String)} when a session ends to prevent unbounded
 * memory growth in long-running brokers. The authorizer's {@code close()} method does not
 * clear the store because multiple broker threads may share a single store.
 */
public final class ClaimStore {

    /** Singleton backing map; never null, never replaced. */
    private static final ConcurrentHashMap<String, Map<String, Object>> STORE =
            new ConcurrentHashMap<>();

    // Prevent instantiation
    private ClaimStore() {}

    /**
     * Stores or replaces the claims associated with the given {@code principal}.
     *
     * @param principal Kafka principal name (non-null, non-blank)
     * @param claims    immutable claim map produced by the validator; must not be null
     */
    public static void put(String principal, Map<String, Object> claims) {
        if (principal == null || principal.isBlank()) {
            throw new IllegalArgumentException("principal must not be null or blank");
        }
        if (claims == null) {
            throw new IllegalArgumentException("claims must not be null");
        }
        STORE.put(principal, claims);
    }

    /**
     * Returns the claims associated with {@code principal}, or an empty map if not found.
     *
     * @param principal Kafka principal name
     * @return unmodifiable claim map, never null
     */
    public static Map<String, Object> get(String principal) {
        if (principal == null) {
            return Collections.emptyMap();
        }
        return STORE.getOrDefault(principal, Collections.emptyMap());
    }

    /**
     * Removes the claims entry for the given {@code principal}.
     *
     * @param principal Kafka principal name; no-op if null or not present
     */
    public static void remove(String principal) {
        if (principal != null) {
            STORE.remove(principal);
        }
    }

    /**
     * Returns the number of principals currently tracked by the store.
     * Primarily useful for monitoring and unit tests.
     *
     * @return current entry count
     */
    public static int size() {
        return STORE.size();
    }

    /**
     * Removes all entries from the store.
     * Should only be called in test teardown or controlled shutdown scenarios.
     */
    public static void clear() {
        STORE.clear();
    }
}
