package com.example.passwordmanager.dto;

import java.time.LocalDateTime;

public record VaultEntryView(Long id, String site, String username, String password,
                             LocalDateTime passwordChangedAt) {
}
