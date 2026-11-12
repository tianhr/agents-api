package io.openkruise.agents.client.runtime;

import java.io.IOException;

/**
 * Supplies a valid traffic access token for a sandbox's data-plane requests.
 *
 * <p>It is invoked immediately before each data-plane request is sent, so a
 * short-lived Traffic JWT can be refreshed transparently. Returning an empty
 * (or {@code null}) token means "no traffic token": the request is sent
 * without the {@code e2b-traffic-access-token} header, preserving the legacy
 * behavior of sandboxes that are not JWT-protected.
 *
 * <p>Throwing an {@link IOException} fails the request before it leaves the
 * process (fail-closed): the SDK refuses to send a request whose token has
 * expired rather than sending a credential the gateway would reject.
 *
 * <p>This is the Java counterpart of the Go SDK's
 * {@code runtime.TrafficTokenProvider} and the Python patch's per-request
 * hooks / gRPC interceptors.
 */
public interface TrafficTokenProvider {

    /**
     * Returns the traffic access token to attach to the next data-plane
     * request, or an empty/{@code null} string to attach none.
     *
     * @throws IOException if a valid token cannot be obtained (fail-closed)
     */
    String get() throws IOException;
}
