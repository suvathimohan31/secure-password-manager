package com.example.passwordmanager.service;

import com.example.passwordmanager.model.UserAccount;
import com.example.passwordmanager.repository.AuditLogRepository;
import com.example.passwordmanager.repository.UserAccountRepository;
import com.example.passwordmanager.repository.VaultEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class VaultServiceAuthorizationTest {

    private VaultEntryRepository vaultRepository;
    private UserAccountRepository userRepository;
    private VaultService vaultService;

    @BeforeEach
    void setUp() {
        vaultRepository = mock(VaultEntryRepository.class);
        userRepository = mock(UserAccountRepository.class);
        UserAccount account = mock(UserAccount.class);
        when(account.getId()).thenReturn(7L);
        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(account));
        vaultService = new VaultService(
                vaultRepository,
                userRepository,
                mock(AuditLogRepository.class),
                mock(VaultCryptoService.class),
                mock(PasswordEncoder.class),
                mock(AuthService.class)
        );
    }

    @Test
    void editLookupScopesEntryByAuthenticatedOwnerAndReturnsNotFoundForAnotherUsersId() {
        when(vaultRepository.findByIdAndUserId(99L, 7L)).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> vaultService.getForm("owner@example.com", 99L, new byte[32]));

        assertEquals(404, exception.getStatusCode().value());
        verify(vaultRepository).findByIdAndUserId(99L, 7L);
    }

    @Test
    void deleteLookupIsAlsoScopedToAuthenticatedOwner() {
        when(vaultRepository.findByIdAndUserId(99L, 7L)).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> vaultService.delete("owner@example.com", 99L));

        assertEquals(404, exception.getStatusCode().value());
        verify(vaultRepository).findByIdAndUserId(99L, 7L);
    }
}
