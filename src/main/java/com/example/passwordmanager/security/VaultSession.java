package com.example.passwordmanager.security;

import jakarta.servlet.http.HttpSession;

import java.util.Arrays;

public final class VaultSession {

    public static final String KEY_ATTRIBUTE = VaultSession.class.getName() + ".key";

    private VaultSession() {
    }

    public static void storeKey(HttpSession session, byte[] key) {
        clearKey(session);
        session.setAttribute(KEY_ATTRIBUTE, key.clone());
    }

    public static byte[] requireKey(HttpSession session) {
        Object value = session.getAttribute(KEY_ATTRIBUTE);
        if (!(value instanceof byte[] key) || key.length != 32) {
            throw new VaultLockedException();
        }
        return key;
    }

    public static void clearKey(HttpSession session) {
        Object value = session.getAttribute(KEY_ATTRIBUTE);
        if (value instanceof byte[] key) {
            Arrays.fill(key, (byte) 0);
        }
        session.removeAttribute(KEY_ATTRIBUTE);
    }

    public static class VaultLockedException extends RuntimeException {
    }
}
