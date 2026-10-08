package com.example.passwordmanager.service;

import com.example.passwordmanager.model.AuditLog;
import com.example.passwordmanager.model.UserAccount;
import com.example.passwordmanager.repository.AuditLogRepository;
import com.example.passwordmanager.repository.UserAccountRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private UserAccountRepository userRepository;
    private AuditLogRepository auditLogRepository;
    private BCryptPasswordEncoder passwordEncoder;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserAccountRepository.class);
        auditLogRepository = mock(AuditLogRepository.class);
        passwordEncoder = new BCryptPasswordEncoder(4);
        authService = new AuthService(userRepository, auditLogRepository, passwordEncoder);
    }

    @Test
    void registerHashesMasterPasswordAndCreatesUniqueVaultSalt() {
        when(userRepository.existsByEmail("student@example.com")).thenReturn(false);
        when(userRepository.save(any(UserAccount.class))).thenAnswer(invocation -> invocation.getArgument(0));

        authService.register(" Student@Example.com ", "a-long-master-password");
        authService.register("student@example.com", "another-long-password");

        var captor = org.mockito.ArgumentCaptor.forClass(UserAccount.class);
        org.mockito.Mockito.verify(userRepository, org.mockito.Mockito.times(2)).save(captor.capture());
        UserAccount first = captor.getAllValues().get(0);
        UserAccount second = captor.getAllValues().get(1);

        assertEquals("student@example.com", first.getEmail());
        assertNotEquals("a-long-master-password", first.getPasswordHash());
        assertTrue(passwordEncoder.matches("a-long-master-password", first.getPasswordHash()));
        assertEquals(32, first.getVaultKdfSalt().length);
        assertFalse(java.util.Arrays.equals(first.getVaultKdfSalt(), second.getVaultKdfSalt()));
        assertEquals("PBKDF2WithHmacSHA256", first.getVaultKdfAlgorithm());
        assertEquals(600_000, first.getVaultKdfIterations());
        verify(auditLogRepository, org.mockito.Mockito.times(2)).save(any(AuditLog.class));
    }

    @Test
    void fifthFailedLoginLocksAccountForFifteenMinutes() {
        UserAccount account = new UserAccount(
                "student@example.com",
                "bcrypt-hash",
                new byte[32],
                "PBKDF2WithHmacSHA256",
                600_000
        );
        when(userRepository.findByEmailForUpdate("student@example.com")).thenReturn(Optional.of(account));

        for (int attempt = 0; attempt < 5; attempt++) {
            authService.recordLoginFailure("STUDENT@example.com");
        }

        assertEquals(5, account.getFailedLoginAttempts());
        assertNotNull(account.getLockedUntil());
        assertTrue(account.getLockedUntil().isAfter(java.time.LocalDateTime.now()));
        verify(auditLogRepository, org.mockito.Mockito.times(5)).save(any(AuditLog.class));
    }
}
