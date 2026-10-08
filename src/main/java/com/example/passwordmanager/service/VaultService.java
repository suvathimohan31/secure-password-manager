package com.example.passwordmanager.service;

import com.example.passwordmanager.dto.VaultEntryForm;
import com.example.passwordmanager.dto.VaultEntryView;
import com.example.passwordmanager.model.AuditLog;
import com.example.passwordmanager.model.UserAccount;
import com.example.passwordmanager.model.VaultEntry;
import com.example.passwordmanager.repository.AuditLogRepository;
import com.example.passwordmanager.repository.UserAccountRepository;
import com.example.passwordmanager.repository.VaultEntryRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.nio.CharBuffer;
import java.util.List;

@Service
public class VaultService {

    private final VaultEntryRepository vaultRepository;
    private final UserAccountRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final VaultCryptoService cryptoService;
    private final PasswordEncoder passwordEncoder;
    private final AuthService authService;

    public VaultService(VaultEntryRepository vaultRepository,
                        UserAccountRepository userRepository,
                        AuditLogRepository auditLogRepository,
                        VaultCryptoService cryptoService,
                        PasswordEncoder passwordEncoder,
                        AuthService authService) {
        this.vaultRepository = vaultRepository;
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
        this.cryptoService = cryptoService;
        this.passwordEncoder = passwordEncoder;
        this.authService = authService;
    }

    public byte[] unlock(String email, char[] masterPassword) {
        UserAccount account = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalStateException("Authenticated account was not found."));
        try {
            if ((account.getLockedUntil() != null && account.getLockedUntil().isAfter(LocalDateTime.now()))
                    || !passwordEncoder.matches(CharBuffer.wrap(masterPassword), account.getPasswordHash())) {
                throw new VaultUnlockException();
            }
            return cryptoService.deriveKey(masterPassword, account.getVaultKdfSalt(),
                    account.getVaultKdfIterations());
        } finally {
            java.util.Arrays.fill(masterPassword, '\0');
        }
    }

    public void recordUnlockSuccess(String email) {
        authService.recordVaultUnlockSuccess(email);
    }

    @Transactional(readOnly = true)
    public List<VaultEntryView> list(String email, byte[] key) {
        UserAccount account = findAccount(email);
        return vaultRepository.findAllByUserIdOrderByUpdatedAtDesc(account.getId()).stream()
                .map(entry -> decrypt(account.getId(), entry, key))
                .toList();
    }

    @Transactional(readOnly = true)
    public VaultEntryForm getForm(String email, Long id, byte[] key) {
        UserAccount account = findAccount(email);
        VaultEntryView view = decrypt(account.getId(), findEntry(id, account.getId()), key);
        VaultEntryForm form = new VaultEntryForm();
        form.setSite(view.site());
        form.setUsername(view.username());
        form.setPassword(view.password());
        return form;
    }

    @Transactional
    public void create(String email, VaultEntryForm form, byte[] key) {
        UserAccount account = findAccount(email);
        VaultCryptoService.EncryptedPayload encrypted = cryptoService.encrypt(
                account.getId(), toVaultData(form), key);
        VaultEntry saved = vaultRepository.save(new VaultEntry(
                account.getId(), encrypted.ciphertext(), encrypted.nonce(), LocalDateTime.now()));
        auditLogRepository.save(new AuditLog(account.getId(), "VAULT_ENTRY_CREATE", saved.getId()));
    }

    @Transactional
    public void update(String email, Long id, VaultEntryForm form, byte[] key) {
        UserAccount account = findAccount(email);
        VaultEntry entry = findEntry(id, account.getId());
        VaultCryptoService.VaultData oldData = cryptoService.decrypt(
                account.getId(), entry.getEncryptedPayload(), entry.getNonce(), key);
        VaultCryptoService.EncryptedPayload encrypted = cryptoService.encrypt(
                account.getId(), toVaultData(form), key);
        boolean passwordChanged = !oldData.password().equals(form.getPassword());
        entry.replaceEncryptedPayload(encrypted.ciphertext(), encrypted.nonce(),
                passwordChanged ? LocalDateTime.now() : entry.getPasswordChangedAt());
        auditLogRepository.save(new AuditLog(account.getId(), "VAULT_ENTRY_UPDATE", id));
    }

    @Transactional
    public void delete(String email, Long id) {
        UserAccount account = findAccount(email);
        VaultEntry entry = findEntry(id, account.getId());
        vaultRepository.delete(entry);
        auditLogRepository.save(new AuditLog(account.getId(), "VAULT_ENTRY_DELETE", id));
    }

    public void recordUnlockFailure(String email) {
        authService.recordVaultUnlockFailure(email);
    }

    private UserAccount findAccount(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalStateException("Authenticated account was not found."));
    }

    private VaultEntry findEntry(Long id, Long userId) {
        return vaultRepository.findByIdAndUserId(id, userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    private VaultEntryView decrypt(long userId, VaultEntry entry, byte[] key) {
        VaultCryptoService.VaultData data = cryptoService.decrypt(
                userId, entry.getEncryptedPayload(), entry.getNonce(), key);
        return new VaultEntryView(entry.getId(), data.site(), data.username(), data.password(),
                entry.getPasswordChangedAt());
    }

    private VaultCryptoService.VaultData toVaultData(VaultEntryForm form) {
        return new VaultCryptoService.VaultData(
                form.getSite().trim(),
                form.getUsername().trim(),
                form.getPassword()
        );
    }

    public static class VaultUnlockException extends RuntimeException {
    }
}
