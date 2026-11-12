package io.openkruise.agents.client.e2b;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * A sandbox traffic access token together with its expiration. Immutable.
 *
 * <p>The Java counterpart of the Go SDK's {@code e2b.TrafficAccessToken}. The
 * expiration is carried as unix seconds (fractional) so the refresh state
 * machine can compare it against a {@code DoubleSupplier} clock without
 * timezone conversions; {@link #getExpiresAtUtc()} renders it back as a
 * zoned timestamp for display and public API consumers.
 */
public final class TrafficAccessToken {

    private final String token;
    private final double expiresAtSeconds;

    /**
     * @param token            the token string (a JWT issued by sandbox-manager)
     * @param expiresAtSeconds the token's expiration as unix seconds (fractional)
     */
    public TrafficAccessToken(String token, double expiresAtSeconds) {
        this.token = token;
        this.expiresAtSeconds = expiresAtSeconds;
    }

    /** The token string (a JWT issued by sandbox-manager). */
    public String getToken() {
        return token;
    }

    /** The token's expiration as unix seconds (fractional). */
    public double getExpiresAtSeconds() {
        return expiresAtSeconds;
    }

    /** The token's expiration as an {@link OffsetDateTime} in UTC. */
    public OffsetDateTime getExpiresAtUtc() {
        long seconds = (long) Math.floor(expiresAtSeconds);
        long nanos = Math.round((expiresAtSeconds - seconds) * 1_000_000_000L);
        return OffsetDateTime.ofInstant(Instant.ofEpochSecond(seconds, nanos), ZoneOffset.UTC);
    }

    @Override
    public String toString() {
        // Never render the token itself: it is a bearer credential.
        return "TrafficAccessToken{expiresAt=" + getExpiresAtUtc() + "}";
    }
}
