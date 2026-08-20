package com.quishguard.sentinel.repository;

import com.quishguard.sentinel.entity.ScanSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ScanSessionRepository extends JpaRepository<ScanSession, UUID> {

    List<ScanSession> findTop5ByUserIdOrderByCreatedAtDesc(UUID userId);
}