package com.quishguard.sentinel.repository;

import com.quishguard.sentinel.entity.UrlAnalysisCache;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface UrlAnalysisCacheRepository extends JpaRepository<UrlAnalysisCache, String> {

    Optional<UrlAnalysisCache> findByUrlHashAndExpiresAtAfter(String urlHash, Instant now);
}