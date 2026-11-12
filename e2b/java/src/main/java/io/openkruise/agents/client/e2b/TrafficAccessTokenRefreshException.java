package io.openkruise.agents.client.e2b;

/**
 * Reports a failed refresh attempt against the management API.
 *
 * <p>The HTTP response body is intentionally neither captured nor rendered, to
 * avoid leaking server error details into client logs; the status code and the
 * requested retry delay are preserved instead.
 *
 * <p>The Java counterpart of the Go SDK's
 * {@code e2b.TrafficAccessTokenRefreshError}.
 */
public class TrafficAccessTokenRefreshException extends TrafficAccessTokenException {

    private static final long serialVersionUID = 1L;

    private final int statusCode;
    private final double retryAfterSeconds;

    /**
     * @param message           human-readable failure summary (never the response body)
     * @param statusCode        the refresh endpoint's HTTP status (0 for transport-level failures)
     * @param retryAfterSeconds the delay requested via the Retry-After header, in seconds (0 if none)
     */
    public TrafficAccessTokenRefreshException(String message, int statusCode, double retryAfterSeconds) {
        super(message);
        this.statusCode = statusCode;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public TrafficAccessTokenRefreshException(String message, int statusCode, double retryAfterSeconds,
        Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    /** The refresh endpoint's HTTP status (0 for transport-level failures). */
    public int getStatusCode() {
        return statusCode;
    }

    /** The delay requested via the Retry-After header, in seconds (0 if none). */
    public double getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
