package com.example.passwordmanager.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordStrengthServiceTest {

    private final PasswordStrengthService strengthService = new PasswordStrengthService();

    @Test
    void identifiesShortSimpleAndCommonPasswordsAsWeak() {
        assertTrue(strengthService.isWeak("short"));
        assertTrue(strengthService.isWeak("alllowercasepassword"));
        assertTrue(strengthService.isWeak("Password123"));
    }

    @Test
    void acceptsLongPasswordWithSeveralCharacterClasses() {
        assertFalse(strengthService.isWeak("A-strong-password-123"));
    }
}
