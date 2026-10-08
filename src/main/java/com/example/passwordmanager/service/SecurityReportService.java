package com.example.passwordmanager.service;

import com.example.passwordmanager.dto.SecurityReport;
import com.example.passwordmanager.dto.VaultEntryView;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
public class SecurityReportService {

    private static final int OLD_PASSWORD_DAYS = 90;
    private final PasswordStrengthService strengthService;

    public SecurityReportService(PasswordStrengthService strengthService) {
        this.strengthService = strengthService;
    }

    public SecurityReport analyze(List<VaultEntryView> entries) {
        Set<Long> weakIds = new HashSet<>();
        Set<Long> oldIds = new HashSet<>();
        Map<String, Integer> passwordUseCounts = new HashMap<>();
        LocalDateTime oldThreshold = LocalDateTime.now().minusDays(OLD_PASSWORD_DAYS);

        for (VaultEntryView entry : entries) {
            if (strengthService.isWeak(entry.password())) {
                weakIds.add(entry.id());
            }
            passwordUseCounts.merge(entry.password(), 1, Integer::sum);
            if (entry.passwordChangedAt() != null && entry.passwordChangedAt().isBefore(oldThreshold)) {
                oldIds.add(entry.id());
            }
        }

        Set<Long> reusedIds = new HashSet<>();
        for (VaultEntryView entry : entries) {
            if (passwordUseCounts.get(entry.password()) > 1) {
                reusedIds.add(entry.id());
            }
        }

        int totalEntries = entries.size();
        int checkCount = totalEntries * 3;
        int warningCount = weakIds.size() + reusedIds.size() + oldIds.size();
        int score = checkCount == 0 ? 0
                : Math.max(0, 100 - (int) Math.round(100.0 * warningCount / checkCount));

        return new SecurityReport(score, totalEntries, weakIds.size(), reusedIds.size(), oldIds.size(),
                Set.copyOf(weakIds), Set.copyOf(reusedIds), Set.copyOf(oldIds));
    }
}
