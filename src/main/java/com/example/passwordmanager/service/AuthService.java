package com.example.passwordmanager.service;

import com.example.passwordmanager.model.AuditLog;
import com.example.passwordmanager.model.UserAccount;
import com.example.passwordmanager.repository.AuditLogRepository;
import com.example.passwordmanager.repository.UserAccountRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Locale;

@Service
public class AuthService {

    private static final int VAULT_SALT_BYTES = 32;
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int MAX_BCRYPT_PASSWORD_BYTES = 72;
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_MINUTES = 15;

    private final UserAccountRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom = new SecureRandom();

    public AuthService(UserAccountRepository userRepository,
                       AuditLogRepository auditLogRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public void register(String email, String password) {
        String normalizedEmail = normalizeEmail(email);
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new EmailAlreadyRegisteredException();
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > MAX_BCRYPT_PASSWORD_BYTES) {
            throw new PasswordTooLongException();
        }

        byte[] salt = new byte[VAULT_SALT_BYTES];
        secureRandom.nextBytes(salt);

        UserAccount account = new UserAccount(
                normalizedEmail,
                passwordEncoder.encode(password),
                salt,
                PBKDF2_ALGORITHM,
                PBKDF2_ITERATIONS
        );
        UserAccount savedAccount = userRepository.save(account);
        auditLogRepository.save(new AuditLog(savedAccount.getId(), "REGISTER"));
    }

    @Transactional
    public void recordLoginFailure(String submittedEmail) {
        String normalizedEmail = normalizeEmail(submittedEmail);
        UserAccount account = userRepository.findByEmailForUpdate(normalizedEmail).orElse(null);
        applyFailedAttempt(account);
        auditLogRepository.save(new AuditLog(account == null ? null : account.getId(), "LOGIN_FAILURE"));
    }

    @Transactional
    public void recordLoginSuccess(String submittedEmail) {
        String normalizedEmail = normalizeEmail(submittedEmail);
        UserAccount account = userRepository.findByEmailForUpdate(normalizedEmail)
                .orElseThrow(() -> new IllegalStateException("Authenticated account was not found."));

        account.setFailedLoginAttempts(0);
        account.setLockedUntil(null);
        account.setLastLoginAt(LocalDateTime.now());
        auditLogRepository.save(new AuditLog(account.getId(), "LOGIN_SUCCESS"));
    }

    @Transactional
    public void recordVaultUnlockFailure(String submittedEmail) {
        UserAccount account = userRepository.findByEmailForUpdate(normalizeEmail(submittedEmail)).orElse(null);
        applyFailedAttempt(account);
        auditLogRepository.save(new AuditLog(
                account == null ? null : account.getId(), "VAULT_UNLOCK_FAILURE"));
    }

    @Transactional
    public void recordVaultUnlockSuccess(String submittedEmail) {
        UserAccount account = userRepository.findByEmailForUpdate(normalizeEmail(submittedEmail))
                .orElseThrow(() -> new IllegalStateException("Authenticated account was not found."));
        account.setFailedLoginAttempts(0);
        account.setLockedUntil(null);
        auditLogRepository.save(new AuditLog(account.getId(), "VAULT_UNLOCK"));
    }

    private void applyFailedAttempt(UserAccount account) {
        if (account == null) {
            return;
        }
        LocalDateTime now = LocalDateTime.now();
        if (account.getLockedUntil() == null || !account.getLockedUntil().isAfter(now)) {
            account.setLockedUntil(null);
            account.setFailedLoginAttempts(account.getFailedLoginAttempts() + 1);
            if (account.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
                account.setLockedUntil(now.plusMinutes(LOCK_MINUTES));
            }
        }
    }

    private String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    public static class EmailAlreadyRegisteredException extends RuntimeException {
    }

    public static class PasswordTooLongException extends RuntimeException {
    }
}
