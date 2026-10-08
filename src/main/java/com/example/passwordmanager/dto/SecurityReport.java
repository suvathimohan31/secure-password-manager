package com.example.passwordmanager.dto;

import java.util.Set;

public record SecurityReport(int score, int totalEntries, int weakCount,
                             int reusedCount, int oldCount,
                             Set<Long> weakEntryIds,
                             Set<Long> reusedEntryIds,
                             Set<Long> oldEntryIds) {
}
