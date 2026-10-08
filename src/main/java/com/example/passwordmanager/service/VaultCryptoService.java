package com.example.passwordmanager.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.IOException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

@Service
public class VaultCryptoService {

    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final byte[] AAD_PREFIX =
            "secure-password-manager:v1:user:".getBytes(StandardCharsets.UTF_8);

    private final ObjectMapper objectMapper;
    private final SecureRandom secureRandom = new SecureRandom();

    public VaultCryptoService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public byte[] deriveKey(char[] masterPassword, byte[] salt, int iterations) {
        if (masterPassword == null || salt == null || salt.length != 32 || iterations < 1) {
            throw new IllegalArgumentException("Invalid key derivation input.");
        }

        PBEKeySpec keySpec = new PBEKeySpec(masterPassword, salt, iterations, KEY_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(keySpec)
                    .getEncoded();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("The configured key derivation algorithm is unavailable.", exception);
        } finally {
            keySpec.clearPassword();
            java.util.Arrays.fill(masterPassword, '\0');
        }
    }

    public EncryptedPayload encrypt(long userId, VaultData data, byte[] key) {
        byte[] plaintext;
        try {
            plaintext = objectMapper.writeValueAsBytes(data);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Vault data could not be serialized.", exception);
        }

        byte[] nonce = new byte[NONCE_BYTES];
        secureRandom.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aadFor(userId));
            return new EncryptedPayload(cipher.doFinal(plaintext), nonce);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Vault data could not be encrypted.", exception);
        } finally {
            java.util.Arrays.fill(plaintext, (byte) 0);
        }
    }

    public VaultData decrypt(long userId, byte[] ciphertext, byte[] nonce, byte[] key) {
        byte[] plaintext;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aadFor(userId));
            plaintext = cipher.doFinal(ciphertext);
        } catch (AEADBadTagException exception) {
            throw new IllegalStateException("Vault authentication failed; data or key may be invalid.", exception);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Vault data could not be decrypted.", exception);
        }

        try {
            return objectMapper.readValue(plaintext, VaultData.class);
        } catch (IOException exception) {
            throw new IllegalStateException("Decrypted vault data has an invalid format.", exception);
        } finally {
            java.util.Arrays.fill(plaintext, (byte) 0);
        }
    }

    private byte[] aadFor(long userId) {
        byte[] id = Long.toString(userId).getBytes(StandardCharsets.US_ASCII);
        byte[] aad = java.util.Arrays.copyOf(AAD_PREFIX, AAD_PREFIX.length + id.length);
        System.arraycopy(id, 0, aad, AAD_PREFIX.length, id.length);
        return aad;
    }

    public record VaultData(String site, String username, String password) {
    }

    public record EncryptedPayload(byte[] ciphertext, byte[] nonce) {
        public EncryptedPayload {
            ciphertext = ciphertext.clone();
            nonce = nonce.clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }

        @Override
        public byte[] nonce() {
            return nonce.clone();
        }
    }
}
