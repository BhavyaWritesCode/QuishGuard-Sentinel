package com.quishguard.sentinel.repository;

import com.quishguard.sentinel.entity.QrResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface QrResultRepository extends JpaRepository<QrResult, UUID> {

    List<QrResult> findBySessionId(UUID sessionId);
}