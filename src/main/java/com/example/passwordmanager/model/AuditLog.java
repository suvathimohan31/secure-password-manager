package com.example.passwordmanager.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.ColumnDefault;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "event_type", nullable = false, length = 40)
    private String eventType;

    @Column(name = "entity_type", length = 40)
    private String entityType;

    @Column(name = "entity_id")
    private Long entityId;

    @Column(name = "occurred_at", nullable = false, insertable = false, updatable = false)
    @ColumnDefault("CURRENT_TIMESTAMP")
    private LocalDateTime occurredAt;

    protected AuditLog() {
    }

    public AuditLog(Long userId, String eventType) {
        this.userId = userId;
        this.eventType = eventType;
    }

    public AuditLog(Long userId, String eventType, Long entityId) {
        this.userId = userId;
        this.eventType = eventType;
        this.entityType = "VAULT_ENTRY";
        this.entityId = entityId;
    }
}
