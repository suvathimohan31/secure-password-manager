package com.example.passwordmanager.service;

import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Set;

@Service
public class PasswordStrengthService {

    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "password", "password123", "123456789012", "qwerty123456",
            "letmein123456", "admin12345678", "iloveyou12345"
    );

    public boolean isWeak(String password) {
        if (password == null || password.length() < 12 || COMMON_PASSWORDS.contains(
                password.toLowerCase(Locale.ROOT))) {
            return true;
        }
        return characterClassCount(password) < 3;
    }

    private int characterClassCount(String password) {
        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        boolean symbol = false;

        for (int i = 0; i < password.length(); i++) {
            char character = password.charAt(i);
            upper |= Character.isUpperCase(character);
            lower |= Character.isLowerCase(character);
            digit |= Character.isDigit(character);
            symbol |= !Character.isLetterOrDigit(character);
        }
        return (upper ? 1 : 0) + (lower ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);
    }
}
