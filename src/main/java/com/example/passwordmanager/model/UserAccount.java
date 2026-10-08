package com.example.passwordmanager.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class UserAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 254)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "vault_kdf_salt", nullable = false, columnDefinition = "BINARY(32)")
    @JdbcTypeCode(SqlTypes.BINARY)
    private byte[] vaultKdfSalt;

    @Column(name = "vault_kdf_algorithm", nullable = false, length = 40)
    private String vaultKdfAlgorithm;

    @Column(name = "vault_kdf_iterations", nullable = false)
    private int vaultKdfIterations;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    @ColumnDefault("CURRENT_TIMESTAMP")
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    @ColumnDefault("CURRENT_TIMESTAMP")
    private LocalDateTime updatedAt;

    protected UserAccount() {
    }

    public UserAccount(String email, String passwordHash, byte[] vaultKdfSalt,
                       String vaultKdfAlgorithm, int vaultKdfIterations) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.vaultKdfSalt = vaultKdfSalt.clone();
        this.vaultKdfAlgorithm = vaultKdfAlgorithm;
        this.vaultKdfIterations = vaultKdfIterations;
    }

    @PrePersist
    @PreUpdate
    private void normalizeEmail() {
        email = email.trim().toLowerCase(java.util.Locale.ROOT);
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public byte[] getVaultKdfSalt() {
        return vaultKdfSalt.clone();
    }

    public String getVaultKdfAlgorithm() {
        return vaultKdfAlgorithm;
    }

    public int getVaultKdfIterations() {
        return vaultKdfIterations;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public void setFailedLoginAttempts(int failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public LocalDateTime getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(LocalDateTime lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    public LocalDateTime getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(LocalDateTime lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }
}
