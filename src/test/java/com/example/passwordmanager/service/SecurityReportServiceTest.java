package com.example.passwordmanager.service;

import com.example.passwordmanager.dto.VaultEntryView;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SecurityReportServiceTest {

    private final SecurityReportService reportService =
            new SecurityReportService(new PasswordStrengthService());

    @Test
    void reportCountsWeakReusedAndOldCredentials() {
        LocalDateTime oldDate = LocalDateTime.now().minusDays(100);
        List<VaultEntryView> entries = List.of(
                new VaultEntryView(1L, "one.example", "one", "A-strong-password-123", oldDate),
                new VaultEntryView(2L, "two.example", "two", "short", oldDate)
        );

        var report = reportService.analyze(entries);

        assertEquals(2, report.totalEntries());
        assertEquals(1, report.weakCount());
        assertEquals(0, report.reusedCount());
        assertEquals(2, report.oldCount());
        assertEquals(50, report.score());
    }

    @Test
    void identicalPasswordsAreFlaggedAsReusedAndEmptyVaultHasNoScore() {
        LocalDateTime recentDate = LocalDateTime.now().minusDays(3);
        String repeated = "A-strong-password-123";
        var report = reportService.analyze(List.of(
                new VaultEntryView(1L, "one.example", "one", repeated, recentDate),
                new VaultEntryView(2L, "two.example", "two", repeated, recentDate)
        ));

        assertEquals(2, report.reusedCount());
        assertEquals(67, report.score());
        assertEquals(0, reportService.analyze(List.of()).score());
    }
}
