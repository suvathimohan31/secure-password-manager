package com.example.passwordmanager.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class VaultSessionTest {

    @Test
    void clearingSessionKeyZeroesItAndMakesVaultLocked() {
        MockHttpSession session = new MockHttpSession();
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 9);
        VaultSession.storeKey(session, key);

        byte[] storedKey = VaultSession.requireKey(session);
        VaultSession.clearKey(session);

        assertArrayEquals(new byte[32], storedKey);
        assertThrows(VaultSession.VaultLockedException.class,
                () -> VaultSession.requireKey(session));
    }

    @Test
    void sessionExpirationZeroesTheVaultKey() {
        MockHttpSession session = new MockHttpSession();
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 4);
        VaultSession.storeKey(session, key);
        byte[] storedKey = VaultSession.requireKey(session);

        new VaultSessionCleanupListener().sessionDestroyed(new jakarta.servlet.http.HttpSessionEvent(session));

        assertArrayEquals(new byte[32], storedKey);
        assertThrows(VaultSession.VaultLockedException.class,
                () -> VaultSession.requireKey(session));
    }
}
