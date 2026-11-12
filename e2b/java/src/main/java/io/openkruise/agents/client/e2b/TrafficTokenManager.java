package io.openkruise.agents.client.e2b;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.DoubleSupplier;

/**
 * Keeps a sandbox's Traffic JWT valid for data-plane requests: it refreshes the
 * token before expiry (coalescing concurrent refreshes into one, with
 * exponential backoff on failure) and fails closed once the token has expired.
 *
 * <p>This is the Java counterpart of the Go SDK's {@code e2b.trafficTokenManager}
 * and the Python {@code kruise_agents} {@code TrafficTokenManager}. Unlike the
 * Go version there is no {@code context}: the refresh is a blocking OkHttp call
 * with its own timeout, and the runtime {@code TrafficTokenProvider} carries no
 * caller cancellation to detach from.
 *
 * <h2>Concurrency</h2>
 * The de-duplication state (generation / attempts / busy) is packed into a
 * single immutable {@link Dedup} object held in one {@code volatile} field and
 * snapshotted with a single read <em>before any lock is taken</em>. Reading the
 * three counters as one atomic snapshot closes the non-atomic window that three
 * separate loads would leave, guaranteeing strict single-flight behavior for
 * concurrent forced refreshes. All mutations of {@link Dedup} and of the token
 * state happen under the write lock.
 */
public final class TrafficTokenManager {

    /** Sandbox metadata entry marking a sandbox as JWT-protected (exact "true"). */
    public static final String JWT_AUTH_METADATA_KEY = "security.agents.kruise.io/enable-jwt-auth";

    // Traffic token refresh tuning, mirroring the Python kruise_agents patch
    // and the Go SDK's e2b/traffic_token.go.
    static final double MIN_REFRESH_AHEAD_SECONDS = 60.0;
    static final double MAX_REFRESH_AHEAD_SECONDS = 300.0;
    static final double REFRESH_AHEAD_FRACTION = 0.2;
    static final double JITTER_FRACTION = 0.1;
    static final double INITIAL_BACKOFF_SECONDS = 1.0;
    static final double MAX_BACKOFF_SECONDS = 30.0;
    static final double EXPIRATION_TOLERANCE_SECONDS = 5.0;

    private static final DoubleSupplier DEFAULT_NOW = () -> System.currentTimeMillis() / 1000.0;
    private static final DoubleSupplier DEFAULT_RANDOM = Math::random;

    /** Obtains a fresh token from the management API. */
    public interface Refresher {
        TrafficAccessToken refresh() throws TrafficAccessTokenException;
    }

    /**
     * Immutable snapshot of the de-duplication counters. {@code generation}
     * counts successful refreshes, {@code attempts} counts refresh attempts
     * (successful or not), and {@code busy} is set while a refresh is in flight.
     */
    private static final class Dedup {
        final long generation;
        final long attempts;
        final boolean busy;

        Dedup(long generation, long attempts, boolean busy) {
            this.generation = generation;
            this.attempts = attempts;
            this.busy = busy;
        }
    }

    private final Refresher refresher;
    private final DoubleSupplier now;
    private final DoubleSupplier random;

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    // Single atomic snapshot of the de-duplication state, read before any lock.
    private volatile Dedup dedup = new Dedup(0L, 0L, false);

    // State below is guarded by lock. "token" is empty (never null) until one is
    // known, matching Go's zero-value string: currentToken() then yields "" for a
    // lazily bootstrapping manager rather than leaking null to callers.
    private String token = "";
    private double expiresAt;   // unix seconds; 0 while no token is known
    private double refreshAt;   // unix seconds; refresh once now >= refreshAt
    private double nextRetry;   // unix seconds; no retry before this time
    private double backoffSeconds;

    /**
     * Builds a manager seeded with an initial token, using the system clock and
     * {@link Math#random()} for jitter.
     *
     * <p>A non-empty token must parse as a JWT; a token that does not (e.g. a
     * legacy opaque UUID) throws and the caller keeps the legacy behavior (no
     * traffic header, no refresh). An empty token creates a lazily bootstrapping
     * manager whose first use triggers the initial refresh.
     */
    public TrafficTokenManager(String token, Refresher refresher) throws TrafficAccessTokenException {
        this(token, refresher, null, null);
    }

    /**
     * Builds a manager with injectable clock and jitter source (used by tests).
     *
     * @param token     the initial token (empty for lazy bootstrap)
     * @param refresher obtains fresh tokens from the management API
     * @param now       current unix time in fractional seconds ({@code null} for the system clock)
     * @param random    pseudo-random float in [0, 1) for jitter ({@code null} for {@link Math#random()})
     * @throws TrafficAccessTokenException if a non-empty seed token is not a valid JWT
     */
    public TrafficTokenManager(String token, Refresher refresher, DoubleSupplier now, DoubleSupplier random)
        throws TrafficAccessTokenException {
        if (refresher == null) {
            throw new IllegalArgumentException("refresher cannot be null");
        }
        this.refresher = refresher;
        this.now = (now != null) ? now : DEFAULT_NOW;
        this.random = (random != null) ? random : DEFAULT_RANDOM;
        this.backoffSeconds = INITIAL_BACKOFF_SECONDS;

        if (token == null || token.isEmpty()) {
            return; // lazy bootstrap: first use triggers the initial refresh
        }
        JwtClaims claims = parseTrafficJwtExpiration(token); // throws if not a JWT
        double issuedAt = claims.hasIat ? claims.issuedAt : this.now.getAsDouble();
        this.token = token;
        this.expiresAt = claims.expiresAt;
        this.refreshAt = calculateRefreshAt(claims.expiresAt, issuedAt);
    }

    /**
     * Returns a token that is safe to send on a data-plane request, refreshing
     * it first when needed. With {@code force} it bypasses the refresh window
     * and backoff, but concurrent forced refreshes are coalesced so only one
     * refresh runs per burst.
     *
     * <p>If a refresh fails while the current token is still valid, the current
     * token is returned (the failure is retried after the backoff). Once the
     * token has expired, a {@link TrafficAccessTokenExpiredException} is thrown
     * instead (the SDK fails closed rather than sending a request the gateway
     * will reject).
     */
    public String ensureValidToken(boolean force) throws TrafficAccessTokenException {
        // Snapshot the de-duplication state before touching any lock: a caller
        // that observes a refresh in progress (or a completed one, or a newer
        // attempt) must not trigger a second refresh. Taking the snapshot here
        // -- before the shared read lock -- matters: while a refresh is in
        // flight the write lock is held, so callers park on the read lock and
        // would otherwise only observe post-completion state.
        Dedup snapshot = dedup;

        // Fast path under a shared read lock: no refresh is due.
        lock.readLock().lock();
        try {
            if (!needsRefreshLocked(force)) {
                return token;
            }
            if (inBackoffLocked(force)) {
                return useCurrentOrRaiseLocked();
            }
        } finally {
            lock.readLock().unlock();
        }

        lock.writeLock().lock();
        try {
            if (force) {
                Dedup current = dedup;
                if (current.generation != snapshot.generation) {
                    // Another thread completed a successful refresh since the
                    // snapshot: the forced refresh is already satisfied.
                    return token;
                }
                if (snapshot.busy || current.attempts != snapshot.attempts) {
                    // A refresh was already in flight at snapshot time, or the
                    // attempt counter advanced since the snapshot: fall back to
                    // the current token instead of starting a second refresh.
                    // "busy" is deliberately the snapshotted value (read before
                    // the lock), matching the Go implementation: an in-flight
                    // refresh that has since failed still leaves busy=false
                    // under the lock, and only the pre-lock snapshot proves the
                    // caller raced an attempt it must coalesce onto.
                    return useCurrentOrRaiseLocked();
                }
            }
            if (!needsRefreshLocked(force)) {
                return token;
            }
            if (inBackoffLocked(force)) {
                return useCurrentOrRaiseLocked();
            }

            markBusy();
            try {
                TrafficAccessTokenException error = null;
                try {
                    error = recordSuccessLocked(refresher.refresh());
                } catch (TrafficAccessTokenException e) {
                    error = e;
                }
                if (error != null) {
                    recordFailureLocked(error);
                    if (now.getAsDouble() >= expiresAt) {
                        throw new TrafficAccessTokenExpiredException(
                            "traffic access token expired before it could be refreshed", error);
                    }
                    return token;
                }
                return token;
            } finally {
                clearBusy();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** Returns the currently cached token without refreshing. */
    public String currentToken() {
        lock.readLock().lock();
        try {
            return token;
        } finally {
            lock.readLock().unlock();
        }
    }

    // --- de-duplication counter mutations (always under the write lock) ---

    private void markBusy() {
        Dedup d = dedup;
        dedup = new Dedup(d.generation, d.attempts + 1, true);
    }

    private void clearBusy() {
        Dedup d = dedup;
        dedup = new Dedup(d.generation, d.attempts, false);
    }

    private void bumpGeneration() {
        Dedup d = dedup;
        dedup = new Dedup(d.generation + 1, d.attempts, d.busy);
    }

    // --- refresh-window / backoff helpers (always under a lock) ---

    /**
     * Computes the time at which a token issued at {@code issuedAt} and expiring
     * at {@code expiresAt} should be refreshed: a fraction of its validity ahead
     * of expiry (bounded to [60s, 300s]) minus a small random jitter.
     */
    private double calculateRefreshAt(double expiresAt, double issuedAt) {
        double validity = expiresAt - issuedAt;
        if (validity < 0) {
            validity = 0;
        }
        double refreshAhead = validity * REFRESH_AHEAD_FRACTION;
        if (refreshAhead < MIN_REFRESH_AHEAD_SECONDS) {
            refreshAhead = MIN_REFRESH_AHEAD_SECONDS;
        }
        if (refreshAhead > MAX_REFRESH_AHEAD_SECONDS) {
            refreshAhead = MAX_REFRESH_AHEAD_SECONDS;
        }
        double jitter = refreshAhead * JITTER_FRACTION * random.getAsDouble();
        return expiresAt - refreshAhead - jitter;
    }

    private boolean needsRefreshLocked(boolean force) {
        return force || token == null || token.isEmpty() || now.getAsDouble() >= refreshAt;
    }

    private boolean inBackoffLocked(boolean force) {
        return !force && now.getAsDouble() < nextRetry;
    }

    /**
     * Returns the current token, failing closed with a
     * {@link TrafficAccessTokenExpiredException} when there is none or it has
     * expired.
     */
    private String useCurrentOrRaiseLocked() throws TrafficAccessTokenExpiredException {
        if (token == null || token.isEmpty() || now.getAsDouble() >= expiresAt) {
            throw new TrafficAccessTokenExpiredException(
                "traffic access token expired before it could be refreshed");
        }
        return token;
    }

    /**
     * Schedules the next retry, honoring the server's Retry-After delay when it
     * exceeds the local backoff, and doubles the backoff up to the cap.
     */
    private void recordFailureLocked(TrafficAccessTokenException error) {
        double delay = backoffSeconds;
        if (error instanceof TrafficAccessTokenRefreshException) {
            double retryAfter = ((TrafficAccessTokenRefreshException) error).getRetryAfterSeconds();
            if (retryAfter > delay) {
                delay = retryAfter;
            }
        }
        nextRetry = now.getAsDouble() + delay;
        backoffSeconds = Math.min(backoffSeconds * 2, MAX_BACKOFF_SECONDS);
    }

    /**
     * Validates a refresh response and installs it as the current token.
     * Validation failures (empty token, JWT that does not parse, expiration
     * mismatching the "exp" claim, already-expired token) are returned as errors
     * and handled by the caller like refresh failures.
     *
     * @return {@code null} on success, otherwise the validation failure
     */
    private TrafficAccessTokenException recordSuccessLocked(TrafficAccessToken result) {
        if (result == null || result.getToken() == null || result.getToken().isEmpty()) {
            return new TrafficAccessTokenException("traffic access token refresh returned an empty token");
        }
        double expiresAtValue = result.getExpiresAtSeconds();
        JwtClaims claims;
        try {
            claims = parseTrafficJwtExpiration(result.getToken());
        } catch (TrafficAccessTokenException e) {
            return e;
        }
        if (Math.abs(claims.expiresAt - expiresAtValue) > EXPIRATION_TOLERANCE_SECONDS) {
            return new TrafficAccessTokenException(
                "traffic access token expiration does not match its exp claim");
        }
        return setTokenLocked(result.getToken(), expiresAtValue, now.getAsDouble());
    }

    /**
     * Installs a token and resets the retry state. A token that is already
     * expired at install time is rejected.
     *
     * @return {@code null} on success, otherwise the rejection reason
     */
    private TrafficAccessTokenException setTokenLocked(String newToken, double expiresAtValue, double issuedAt) {
        if (expiresAtValue <= now.getAsDouble()) {
            return new TrafficAccessTokenException("traffic access token refresh returned an expired token");
        }
        this.token = newToken;
        this.expiresAt = expiresAtValue;
        this.refreshAt = calculateRefreshAt(expiresAtValue, issuedAt);
        this.nextRetry = 0;
        this.backoffSeconds = INITIAL_BACKOFF_SECONDS;
        bumpGeneration();
        return null;
    }

    // --- parsing helpers (package-visible for tests) ---

    /**
     * Reports whether sandbox metadata marks it as protected by sandbox-gateway
     * JWT auth (exact "true" value, matching the Python implementation).
     */
    static boolean requiresTrafficToken(Map<String, String> metadata) {
        return metadata != null && "true".equals(metadata.get(JWT_AUTH_METADATA_KEY));
    }

    /** Carries the expiration-related claims of a Traffic JWT. */
    static final class JwtClaims {
        double expiresAt; // "exp" claim as unix seconds
        double issuedAt;  // "iat" claim as unix seconds; valid only when hasIat
        boolean hasIat;
    }

    /**
     * Extracts the "exp" (required) and "iat" (optional) claims from a JWT
     * without verifying its signature: the token is only used client-side for
     * refresh scheduling, authenticity is enforced by the sandbox-gateway.
     */
    static JwtClaims parseTrafficJwtExpiration(String token) throws TrafficAccessTokenException {
        if (token == null) {
            throw parseError();
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length < 2) {
            throw parseError();
        }
        byte[] payload;
        try {
            // Accept padded or unpadded base64url payloads.
            payload = Base64.getUrlDecoder().decode(trimTrailingEquals(parts[1]));
        } catch (IllegalArgumentException e) {
            throw parseError();
        }
        JsonObject claims;
        try {
            JsonElement element = JsonParser.parseString(new String(payload, StandardCharsets.UTF_8));
            if (!element.isJsonObject()) {
                throw parseError();
            }
            claims = element.getAsJsonObject();
        } catch (JsonSyntaxException e) {
            throw parseError();
        }
        Double exp = numericClaim(claims, "exp");
        if (exp == null) {
            throw parseError();
        }
        JwtClaims parsed = new JwtClaims();
        parsed.expiresAt = exp;
        Double iat = numericClaim(claims, "iat");
        if (iat != null) {
            parsed.issuedAt = iat;
            parsed.hasIat = true;
        }
        return parsed;
    }

    /**
     * Extracts a numeric claim from decoded JWT claims. Only JSON numbers are
     * accepted (real JWTs encode numeric dates as numbers), matching the Go
     * implementation's {@code float64} type assertion.
     */
    private static Double numericClaim(JsonObject claims, String name) {
        JsonElement element = claims.get(name);
        if (element == null || !element.isJsonPrimitive()) {
            return null;
        }
        JsonPrimitive primitive = element.getAsJsonPrimitive();
        if (!primitive.isNumber()) {
            return null;
        }
        return primitive.getAsDouble();
    }

    private static TrafficAccessTokenException parseError() {
        return new TrafficAccessTokenException("traffic access token is not a JWT with a valid exp claim");
    }

    private static String trimTrailingEquals(String value) {
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == '=') {
            end--;
        }
        return value.substring(0, end);
    }

    /**
     * Parses an RFC3339 timestamp with a mandatory timezone, the counterpart of
     * the Python patch's {@code parse_expiration} and the Go SDK's
     * {@code parseTrafficTokenExpiration}.
     */
    static OffsetDateTime parseTrafficTokenExpiration(String value) throws TrafficAccessTokenException {
        try {
            // ISO_OFFSET_DATE_TIME requires a zone offset, so a timezone is
            // always present (matching Go's time.RFC3339).
            return OffsetDateTime.parse(value.trim());
        } catch (DateTimeParseException | NullPointerException e) {
            throw new TrafficAccessTokenException("invalid traffic access token expiration", e);
        }
    }

    /**
     * Parses the Retry-After header as delay seconds; the only form the manager
     * understands (HTTP-date values are ignored, matching the Python and Go
     * implementations).
     */
    static double parseRetryAfter(String value) {
        if (value == null) {
            return 0;
        }
        try {
            double seconds = Double.parseDouble(value.trim());
            if (seconds < 0 || Double.isNaN(seconds) || Double.isInfinite(seconds)) {
                return 0;
            }
            return seconds;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
