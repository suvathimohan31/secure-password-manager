package com.example.passwordmanager.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class VaultCryptoServiceTest {

    private final VaultCryptoService cryptoService = new VaultCryptoService(new ObjectMapper());

    @Test
    void encryptedPayloadRoundTripsAndIsBoundToItsOwner() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 7);
        VaultCryptoService.VaultData expected =
                new VaultCryptoService.VaultData("example.com", "student", "secret-password");

        VaultCryptoService.EncryptedPayload encrypted =
                cryptoService.encrypt(42L, expected, key);

        assertFalse(new String(encrypted.ciphertext(), java.nio.charset.StandardCharsets.ISO_8859_1)
                .contains("secret-password"));
        assertEquals(expected, cryptoService.decrypt(
                42L, encrypted.ciphertext(), encrypted.nonce(), key));
        assertThrows(IllegalStateException.class, () ->
                cryptoService.decrypt(43L, encrypted.ciphertext(), encrypted.nonce(), key));
    }

    @Test
    void derivedKeyIsThirtyTwoBytesAndClearsTheProvidedPasswordBuffer() {
        byte[] salt = new byte[32];
        Arrays.fill(salt, (byte) 3);
        char[] password = "test-master-password".toCharArray();

        byte[] key = cryptoService.deriveKey(password, salt, 1_000);

        assertEquals(32, key.length);
        assertArrayEquals(new char[password.length], password);
    }
}
