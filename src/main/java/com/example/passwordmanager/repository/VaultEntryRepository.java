package com.example.passwordmanager.repository;

import com.example.passwordmanager.model.VaultEntry;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface VaultEntryRepository extends JpaRepository<VaultEntry, Long> {

    List<VaultEntry> findAllByUserIdOrderByUpdatedAtDesc(Long userId);

    Optional<VaultEntry> findByIdAndUserId(Long id, Long userId);

    void deleteByIdAndUserId(Long id, Long userId);
}
