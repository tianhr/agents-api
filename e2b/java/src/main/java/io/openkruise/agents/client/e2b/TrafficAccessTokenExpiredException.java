package io.openkruise.agents.client.e2b;

/**
 * Raised before a data-plane request would use an expired token: the SDK fails
 * closed, refusing to send a request whose token has expired until a refresh
 * succeeds.
 *
 * <p>The Java counterpart of the Go SDK's {@code e2b.TrafficAccessTokenExpired}.
 * The {@linkplain #getCause() cause}, when present, is the refresh failure that
 * left the token expired.
 */
public class TrafficAccessTokenExpiredException extends TrafficAccessTokenException {

    private static final long serialVersionUID = 1L;

    public TrafficAccessTokenExpiredException(String message) {
        super(message);
    }

    public TrafficAccessTokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
