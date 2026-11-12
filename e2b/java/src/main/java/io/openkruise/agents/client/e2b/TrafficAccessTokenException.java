package io.openkruise.agents.client.e2b;

import java.io.IOException;

/**
 * Base exception for local traffic access token handling: JWT parse failures,
 * malformed refresh responses and expiry.
 *
 * <p>It extends {@link IOException} so it propagates naturally through the
 * runtime {@code TrafficTokenProvider} (whose {@code get()} declares
 * {@code IOException}) and OkHttp call chains, letting a data-plane request
 * fail closed rather than sending a credential the gateway would reject.
 *
 * <p>The Java counterpart of the Go SDK's {@code e2b.TrafficAccessTokenError}.
 */
public class TrafficAccessTokenException extends IOException {

    private static final long serialVersionUID = 1L;

    public TrafficAccessTokenException(String message) {
        super(message);
    }

    public TrafficAccessTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
