package io.openkruise.agents.client.e2b;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Golden-value tests for {@link Keys#encodeForE2BSDK(String)}. The expected
 * values are byte-for-byte identical to the Go SDK's {@code e2b/keys_test.go}
 * and the Python {@code kruise_agents} {@code tests/test_keys.py}, locking
 * wire-format parity across all three SDKs and the upstream sandbox-manager
 * compat encoder.
 */
public class KeysTest {

    @Test
    public void encodeForE2BSDKGolden() {
        // Empty input.
        assertEquals("e2b_6f6b61670100000000425929dd6afb855b", Keys.encodeForE2BSDK(""));
        // Admin key.
        assertEquals("e2b_6f6b6167010000000961646d696e2d6b6579c4341091192d130a",
            Keys.encodeForE2BSDK("admin-key"));
        // UUID-style key.
        assertEquals(
            "e2b_6f6b6167010000002435623134613538662d393366342d346433652d396139322d3266336530653161396533331d5464e1669224e7",
            Keys.encodeForE2BSDK("5b14a58f-93f4-4d3e-9a92-2f3e0e1a9e33"));
    }

    @Test
    public void encodeForE2BSDKStructure() {
        String raw = "some-random-key";
        String encoded = Keys.encodeForE2BSDK(raw);

        // header = prefix + magic + version + 8-hex length.
        int headerLen = Keys.E2B_SDK_COMPAT_PREFIX.length()
            + Keys.E2B_SDK_COMPAT_MAGIC.length()
            + Keys.E2B_SDK_COMPAT_VERSION.length()
            + 8;
        assertTrue("encoded key too short for header + checksum", encoded.length() >= headerLen + 16);

        // "some-random-key" is 15 bytes = 0x0f, rendered as 8 lowercase hex digits.
        assertEquals("e2b_6f6b6167010000000f", encoded.substring(0, headerLen));

        // The body is 2 hex chars per byte, and the checksum is always the last
        // 16 hex characters (8 bytes).
        assertEquals(2 * raw.length() + 16, encoded.length() - headerLen);
    }
}
