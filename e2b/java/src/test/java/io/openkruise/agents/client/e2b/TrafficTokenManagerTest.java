package io.openkruise.agents.client.e2b;

import com.google.gson.JsonObject;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.DoubleFunction;
import java.util.function.DoubleSupplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * State-machine tests for {@link TrafficTokenManager}, ported case-for-case
 * from the Go SDK's {@code e2b/traffic_token_test.go} (which mirrors the
 * Python {@code kruise_agents} tests). Deterministic time comes from
 * {@link FakeClock}, jitter is pinned to zero, and refreshes are served by
 * {@link MockRefresh} or gate-controlled {@link TrafficTokenManager.Refresher}
 * lambdas so the concurrency cases are reproducible.
 *
 * <p>The Go {@code TestTrafficTokenManagerRefreshDetachedFromCallerCancel}
 * case is intentionally omitted: the Java provider carries no caller
 * {@code context} to detach from (a structural non-gap noted in the plan).
 */
public class TrafficTokenManagerTest {

    /** Fixed zero jitter keeps refresh scheduling deterministic. */
    private static final DoubleSupplier ZERO_RANDOM = () -> 0.0;

    // --- parsing helpers ---

    @Test
    public void parseTrafficJwtExpiration() throws Exception {
        double now = 1_000_000.0;
        TrafficTokenManager.JwtClaims claims =
            TrafficTokenManager.parseTrafficJwtExpiration(tokenWithValidity(now, 60));
        assertEquals(now + 60, claims.expiresAt, 0.0);
        assertTrue("iat should be present", claims.hasIat);
        assertEquals(now, claims.issuedAt, 0.0);

        // Missing exp / invalid JWT / non-numeric exp are all parse errors.
        JsonObject iatOnly = new JsonObject();
        iatOnly.addProperty("iat", now);
        JsonObject expString = new JsonObject();
        expString.addProperty("exp", "later");
        String[] bad = {"not-a-jwt", "onlytwo", signTestJwt(iatOnly), signTestJwt(expString)};
        for (String token : bad) {
            try {
                TrafficTokenManager.parseTrafficJwtExpiration(token);
                fail("parse(" + token + ") unexpectedly succeeded");
            } catch (TrafficAccessTokenException expected) {
                // wanted
            }
        }

        // iat is optional.
        JsonObject expOnly = new JsonObject();
        expOnly.addProperty("exp", now + 60);
        TrafficTokenManager.JwtClaims noIat = TrafficTokenManager.parseTrafficJwtExpiration(signTestJwt(expOnly));
        assertFalse("iat should be absent", noIat.hasIat);
    }

    @Test
    public void parseTrafficTokenExpiration() throws Exception {
        OffsetDateTime parsed = TrafficTokenManager.parseTrafficTokenExpiration("2026-01-02T03:04:05Z");
        assertEquals(Instant.parse("2026-01-02T03:04:05Z"), parsed.toInstant());

        // Empty / malformed / missing-timezone are all rejected.
        String[] bad = {"", "not-a-time", "2026-01-02T03:04:05"};
        for (String value : bad) {
            try {
                TrafficTokenManager.parseTrafficTokenExpiration(value);
                fail("parse(" + value + ") unexpectedly succeeded");
            } catch (TrafficAccessTokenException expected) {
                // wanted
            }
        }
    }

    @Test
    public void parseRetryAfter() {
        assertEquals(2.0, TrafficTokenManager.parseRetryAfter("2"), 0.0);
        assertEquals(1.5, TrafficTokenManager.parseRetryAfter("1.5"), 0.0);
        assertEquals(3.0, TrafficTokenManager.parseRetryAfter(" 3 "), 0.0);
        assertEquals(0.0, TrafficTokenManager.parseRetryAfter(""), 0.0);
        assertEquals(0.0, TrafficTokenManager.parseRetryAfter("-1"), 0.0);
        // HTTP-date form is not understood.
        assertEquals(0.0, TrafficTokenManager.parseRetryAfter("abc"), 0.0);
        assertEquals(0.0, TrafficTokenManager.parseRetryAfter("NaN"), 0.0);
        // +Inf.
        assertEquals(0.0, TrafficTokenManager.parseRetryAfter("1e999"), 0.0);
        assertEquals(0.0, TrafficTokenManager.parseRetryAfter("not-a-number"), 0.0);
    }

    @Test
    public void requiresTrafficToken() {
        Map<String, String> enabled = new HashMap<>();
        enabled.put(TrafficTokenManager.JWT_AUTH_METADATA_KEY, "true");
        assertTrue(TrafficTokenManager.requiresTrafficToken(enabled));

        // Exact "true" match only.
        Map<String, String> capitalised = new HashMap<>();
        capitalised.put(TrafficTokenManager.JWT_AUTH_METADATA_KEY, "True");
        assertFalse(TrafficTokenManager.requiresTrafficToken(capitalised));

        Map<String, String> disabled = new HashMap<>();
        disabled.put(TrafficTokenManager.JWT_AUTH_METADATA_KEY, "false");
        assertFalse(TrafficTokenManager.requiresTrafficToken(disabled));

        Map<String, String> other = new HashMap<>();
        other.put("other", "true");
        assertFalse(TrafficTokenManager.requiresTrafficToken(other));

        assertFalse(TrafficTokenManager.requiresTrafficToken(null));
    }

    // --- construction ---

    @Test
    public void newManagerRejectsNonJwt() throws Exception {
        FakeClock clock = new FakeClock(1_000_000);
        MockRefresh refresh = new MockRefresh();

        try {
            new TrafficTokenManager("opaque-uuid-style-token", refresh, clock, ZERO_RANDOM);
            fail("non-JWT seed token should be rejected");
        } catch (TrafficAccessTokenException expected) {
            // wanted
        }

        // Empty token is fine (lazy bootstrap).
        new TrafficTokenManager("", refresh, clock, ZERO_RANDOM);
    }

    // --- refresh scheduling ---

    @Test
    public void refreshesBeforeExpiry() throws Exception {
        // 3600s validity -> refresh ahead = min(300, max(60, 720)) = 300s.
        FakeClock clock = new FakeClock(1_000_000);
        String first = tokenWithValidity(clock.now, 3600);
        String second = tokenWithValidity(clock.now + 3000, 3600);
        MockRefresh refresh = new MockRefresh(second);

        TrafficTokenManager m = new TrafficTokenManager(first, refresh, clock, ZERO_RANDOM);

        // Well before the refresh point: no refresh yet.
        assertEquals(first, m.ensureValidToken(false));
        assertEquals(0, refresh.calls.get());

        // Crossing refresh_at (exp - 300s) triggers the refresh.
        clock.advance(3301);
        assertEquals(second, m.ensureValidToken(false));
        assertEquals(1, refresh.calls.get());
    }

    @Test
    public void emptyTokenBootstraps() throws Exception {
        FakeClock clock = new FakeClock(1_000_000);
        String token = tokenWithValidity(clock.now, 600);
        MockRefresh refresh = new MockRefresh(token);

        TrafficTokenManager m = new TrafficTokenManager("", refresh, clock, ZERO_RANDOM);
        assertEquals(token, m.ensureValidToken(false));
    }

    @Test
    public void forcedRefresh() throws Exception {
        FakeClock clock = new FakeClock(1_000_000);
        String first = tokenWithValidity(clock.now, 3600);
        String second = tokenWithValidity(clock.now, 3600);
        MockRefresh refresh = new MockRefresh(second);

        TrafficTokenManager m = new TrafficTokenManager(first, refresh, clock, ZERO_RANDOM);
        assertEquals(second, m.ensureValidToken(true));
        assertEquals(1, refresh.calls.get());
    }

    @Test
    public void failureKeepsCurrentToken() throws Exception {
        FakeClock clock = new FakeClock(1_000_000);
        String current = tokenWithValidity(clock.now, 3600);
        MockRefresh refresh = new MockRefresh();
        refresh.err = new TrafficAccessTokenRefreshException("boom", 0, 0);

        TrafficTokenManager m = new TrafficTokenManager(current, refresh, clock, ZERO_RANDOM);

        // Not yet due: current token, no refresh.
        assertEquals(current, m.ensureValidToken(false));

        // Past refresh_at: the refresh fails but the token is still valid.
        clock.advance(3301);
        assertEquals(current, m.ensureValidToken(false));

        // Backoff: a second immediate call must not hammer the endpoint.
        assertEquals(current, m.ensureValidToken(false));
        assertEquals("backoff should suppress the second refresh", 1, refresh.calls.get());

        // After the backoff elapses the retry happens; success replaces the token.
        clock.advance(1);
        String second = tokenWithValidity(clock.now, 3600);
        refresh.err = null;
        refresh.setTokens(second);
        assertEquals(second, m.ensureValidToken(false));
    }

    @Test
    public void failClosedAfterExpiry() throws Exception {
        FakeClock clock = new FakeClock(1_000_000);
        String shortLived = tokenWithValidity(clock.now, 60);
        MockRefresh refresh = new MockRefresh();
        refresh.err = new TrafficAccessTokenRefreshException("down", 0, 0);

        TrafficTokenManager m = new TrafficTokenManager(shortLived, refresh, clock, ZERO_RANDOM);

        // 60s validity -> refresh ahead = max(60, 12) = 60 -> refreshAt = exp - 60
        // = now. The first call already refreshes and fails but the token is
        // still valid, so it is returned.
        assertEquals(shortLived, m.ensureValidToken(false));

        // Token expired: the SDK fails closed.
        clock.advance(61);
        try {
            m.ensureValidToken(false);
            fail("want TrafficAccessTokenExpiredException after expiry");
        } catch (TrafficAccessTokenExpiredException expected) {
            // wanted
        }
    }

    @Test
    public void retryAfterHonored() throws Exception {
        FakeClock clock = new FakeClock(1_000_000);
        String current = tokenWithValidity(clock.now, 3600);
        MockRefresh refresh = new MockRefresh();
        refresh.err = new TrafficAccessTokenRefreshException("rate limited", 429, 10);

        TrafficTokenManager m = new TrafficTokenManager(current, refresh, clock, ZERO_RANDOM);
        clock.advance(3301); // past refresh_at

        // First failure schedules the retry 10s out (server's Retry-After).
        assertEquals(current, m.ensureValidToken(false));

        // 9s later still in backoff.
        clock.advance(9);
        assertEquals(current, m.ensureValidToken(false));
        assertEquals("Retry-After should suppress the retry", 1, refresh.calls.get());

        // 1s more: retry succeeds.
        clock.advance(1);
        String second = tokenWithValidity(clock.now, 3600);
        refresh.err = null;
        refresh.setTokens(second);
        assertEquals(second, m.ensureValidToken(false));
    }

    // --- refresh response validation ---

    @Test
    public void responseValidation() throws Exception {
        // Each case gets a fresh clock and current token; the response is
        // mutated to be invalid while the reported/token expirations vary.
        // (1) Token says exp = now+3600 but the response reports now+1200.
        assertKeepsCurrentAfterInvalidResponse(
            now -> new TrafficAccessToken(tokenWithValidity(now, 3600), now + 1200));
        // (2) Token and reported expiration agree, but both are in the past.
        assertKeepsCurrentAfterInvalidResponse(
            now -> new TrafficAccessToken(tokenWithValidity(now - 10, 5), now - 5));
        // (3) Empty token.
        assertKeepsCurrentAfterInvalidResponse(
            now -> new TrafficAccessToken("", now + 3600));
        // (4) Reported expiration is fine, but the token is not a JWT at all.
        assertKeepsCurrentAfterInvalidResponse(
            now -> new TrafficAccessToken("not-a-jwt", now + 3600));
    }

    private void assertKeepsCurrentAfterInvalidResponse(DoubleFunction<TrafficAccessToken> respond)
        throws Exception {
        FakeClock clock = new FakeClock(1_000_000);
        String current = tokenWithValidity(clock.now, 3600);
        TrafficTokenManager m = new TrafficTokenManager(current,
            () -> respond.apply(clock.now), clock, ZERO_RANDOM);
        clock.advance(3301); // past refresh_at
        assertEquals("invalid refresh response should keep the current token",
            current, m.ensureValidToken(false));
    }

    // --- concurrency: single-flight coalescing ---

    @Test
    public void concurrentRefreshCoalesced() throws Exception {
        FakeClock clock = new FakeClock(1_000_000);
        String current = tokenWithValidity(clock.now, 3600);

        // Slow refresh: hand out the token only after all callers are blocked.
        CountDownLatch gate = new CountDownLatch(1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger refreshCalls = new AtomicInteger();
        TrafficTokenManager.Refresher refresher = () -> {
            refreshCalls.incrementAndGet();
            awaitQuietly(gate);
            String token = tokenWithValidity(clock.now, 3600);
            return new TrafficAccessToken(token, jwtExp(token));
        };

        TrafficTokenManager m = new TrafficTokenManager(current, refresher, clock, ZERO_RANDOM);
        clock.advance(3301); // everyone needs a refresh

        int callers = 8;
        Thread[] threads = new Thread[callers];
        for (int i = 0; i < callers; i++) {
            threads[i] = new Thread(() -> {
                awaitQuietly(start);
                try {
                    m.ensureValidToken(false);
                } catch (Exception ignored) {
                    // the coalesced callers all succeed; ignore any edge failure
                }
            });
            threads[i].start();
        }
        start.countDown();
        // Let the callers pile up behind the write lock, then release the refresh.
        Thread.sleep(50);
        gate.countDown();
        for (Thread t : threads) {
            t.join();
        }

        assertEquals("concurrent refresh calls should coalesce to 1", 1, refreshCalls.get());
    }

    @Test
    public void forcedRefreshCoalescedWhileInFlight() throws Exception {
        FakeClock clock = new FakeClock(1_000_000);
        String current = tokenWithValidity(clock.now, 3600);

        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch gate = new CountDownLatch(1);
        AtomicInteger refreshCalls = new AtomicInteger();
        TrafficTokenManager.Refresher refresher = () -> {
            refreshCalls.incrementAndGet();
            // Signal that a refresh is in flight, then hold it open.
            entered.countDown();
            awaitQuietly(gate);
            String token = tokenWithValidity(clock.now, 3600);
            return new TrafficAccessToken(token, jwtExp(token));
        };

        TrafficTokenManager m = new TrafficTokenManager(current, refresher, clock, ZERO_RANDOM);

        // Caller 1 starts a forced refresh and parks inside it (holding the
        // write lock, exactly like a real in-flight refresh).
        Thread caller1 = new Thread(() -> {
            try {
                m.ensureValidToken(true);
            } catch (Exception ignored) {
                // expected to succeed
            }
        });
        caller1.start();
        entered.await();

        // While the refresh is in flight, concurrent forced callers must
        // coalesce onto it instead of starting their own refresh: they snapshot
        // the in-flight state before parking on the lock.
        int lateCallers = 4;
        AtomicInteger lateEntered = new AtomicInteger();
        Thread[] late = new Thread[lateCallers];
        for (int i = 0; i < lateCallers; i++) {
            late[i] = new Thread(() -> {
                lateEntered.incrementAndGet();
                try {
                    m.ensureValidToken(true);
                } catch (Exception ignored) {
                    // expected to succeed
                }
            });
            late[i].start();
        }
        // Let every late caller take its pre-lock snapshot before releasing the
        // refresh (snapshotting is the first thing ensureValidToken does).
        while (lateEntered.get() < lateCallers) {
            Thread.sleep(1);
        }
        Thread.sleep(25);

        gate.countDown();
        caller1.join();
        for (Thread t : late) {
            t.join();
        }
        assertEquals("in-flight forced callers should coalesce to 1 refresh", 1, refreshCalls.get());
    }

    @Test
    public void forcedRefreshFailureCoalesced() throws Exception {
        FakeClock clock = new FakeClock(1_000_000);
        String current = tokenWithValidity(clock.now, 3600);

        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch gate = new CountDownLatch(1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger refreshCalls = new AtomicInteger();
        AtomicInteger started = new AtomicInteger();
        TrafficTokenManager.Refresher refresher = () -> {
            refreshCalls.incrementAndGet();
            entered.countDown();
            awaitQuietly(gate);
            // The in-flight refresh fails: concurrent forced callers must
            // coalesce onto this single attempt and keep the current token.
            throw new TrafficAccessTokenRefreshException("unavailable", 0, 0);
        };

        TrafficTokenManager m = new TrafficTokenManager(current, refresher, clock, ZERO_RANDOM);

        int callers = 8;
        String[] results = new String[callers];
        Thread[] threads = new Thread[callers];
        for (int i = 0; i < callers; i++) {
            final int idx = i;
            threads[i] = new Thread(() -> {
                awaitQuietly(start);
                started.incrementAndGet();
                try {
                    results[idx] = m.ensureValidToken(true);
                } catch (Exception ignored) {
                    // a failed forced refresh still returns the current token
                }
            });
            threads[i].start();
        }
        start.countDown();
        entered.await(); // the single refresh is in flight
        // Let the remaining callers take their pre-lock snapshots while the
        // refresh is held open, then let it fail.
        while (started.get() < callers) {
            Thread.sleep(1);
        }
        Thread.sleep(25);
        gate.countDown();
        for (Thread t : threads) {
            t.join();
        }

        for (int i = 0; i < callers; i++) {
            assertEquals("caller " + i + " should keep the current token", current, results[i]);
        }
        assertEquals("failed forced refreshes should coalesce to 1", 1, refreshCalls.get());
    }

    @Test
    public void forcedRefreshAfterCompletionRefreshesAgain() throws Exception {
        FakeClock clock = new FakeClock(1_000_000);
        String current = tokenWithValidity(clock.now, 3600);

        AtomicInteger refreshCalls = new AtomicInteger();
        TrafficTokenManager.Refresher refresher = () -> {
            refreshCalls.incrementAndGet();
            String token = tokenWithValidity(clock.now, 3600);
            return new TrafficAccessToken(token, jwtExp(token));
        };

        TrafficTokenManager m = new TrafficTokenManager(current, refresher, clock, ZERO_RANDOM);

        // "Force" means "give me a new token": a forced call after a completed
        // refresh must refresh again (each call yields a fresh token).
        m.ensureValidToken(true);
        m.ensureValidToken(true);
        assertEquals(2, refreshCalls.get());
    }

    // --- test helpers ---

    /** Drives deterministic time; {@code now} is volatile for cross-thread reads. */
    private static final class FakeClock implements DoubleSupplier {
        private volatile double now;

        FakeClock(double now) {
            this.now = now;
        }

        @Override
        public double getAsDouble() {
            return now;
        }

        void advance(double seconds) {
            now += seconds;
        }
    }

    /** Counts refresh calls and hands out successive queued tokens. */
    private static final class MockRefresh implements TrafficTokenManager.Refresher {
        final AtomicInteger calls = new AtomicInteger();
        final Queue<String> tokens = new ArrayDeque<>();
        volatile TrafficAccessTokenException err;

        MockRefresh(String... initial) {
            Collections.addAll(tokens, initial);
        }

        void setTokens(String... next) {
            tokens.clear();
            Collections.addAll(tokens, next);
        }

        @Override
        public TrafficAccessToken refresh() throws TrafficAccessTokenException {
            calls.incrementAndGet();
            if (err != null) {
                throw err;
            }
            String token = tokens.poll();
            if (token == null) {
                throw new IllegalStateException("mockRefresh: no token queued");
            }
            return new TrafficAccessToken(token, jwtExp(token));
        }
    }

    /** Builds an unsigned JWT carrying the given claims (signature not verified client-side). */
    private static String signTestJwt(JsonObject claims) {
        String body = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(claims.toString().getBytes(StandardCharsets.UTF_8));
        return "header." + body + ".signature";
    }

    /** Returns a JWT expiring at {@code now + validity} seconds, issued at {@code now}. */
    private static String tokenWithValidity(double now, double validity) {
        JsonObject claims = new JsonObject();
        claims.addProperty("exp", now + validity);
        claims.addProperty("iat", now);
        return signTestJwt(claims);
    }

    /** Extracts the "exp" claim of a test token. */
    private static double jwtExp(String token) throws TrafficAccessTokenException {
        return TrafficTokenManager.parseTrafficJwtExpiration(token).expiresAt;
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while awaiting latch", e);
        }
    }
}
