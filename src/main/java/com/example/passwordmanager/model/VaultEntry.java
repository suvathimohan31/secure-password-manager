package com.example.passwordmanager.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;

@Entity
@Table(name = "vault_entries")
public class VaultEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "encrypted_payload", nullable = false, columnDefinition = "MEDIUMBLOB")
    @JdbcTypeCode(SqlTypes.LONGVARBINARY)
    private byte[] encryptedPayload;

    @Column(nullable = false, columnDefinition = "BINARY(12)")
    @JdbcTypeCode(SqlTypes.BINARY)
    private byte[] nonce;

    @Column(name = "encryption_version", nullable = false)
    private short encryptionVersion = 1;

    @Column(name = "password_changed_at")
    private LocalDateTime passwordChangedAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    @ColumnDefault("CURRENT_TIMESTAMP")
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    @ColumnDefault("CURRENT_TIMESTAMP")
    private LocalDateTime updatedAt;

    protected VaultEntry() {
    }

    public VaultEntry(Long userId, byte[] encryptedPayload, byte[] nonce,
                      LocalDateTime passwordChangedAt) {
        this.userId = userId;
        this.encryptedPayload = encryptedPayload.clone();
        this.nonce = nonce.clone();
        this.passwordChangedAt = passwordChangedAt;
    }

    public void replaceEncryptedPayload(byte[] encryptedPayload, byte[] nonce,
                                        LocalDateTime passwordChangedAt) {
        this.encryptedPayload = encryptedPayload.clone();
        this.nonce = nonce.clone();
        this.passwordChangedAt = passwordChangedAt;
    }

    public Long getId() {
        return id;
    }

    public Long getUserId() {
        return userId;
    }

    public byte[] getEncryptedPayload() {
        return encryptedPayload.clone();
    }

    public byte[] getNonce() {
        return nonce.clone();
    }

    public short getEncryptionVersion() {
        return encryptionVersion;
    }

    public LocalDateTime getPasswordChangedAt() {
        return passwordChangedAt;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }
}
