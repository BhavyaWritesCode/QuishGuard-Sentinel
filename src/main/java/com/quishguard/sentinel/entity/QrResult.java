package com.quishguard.sentinel.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "qr_results")
@Getter
@Setter
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class QrResult {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "session_id", nullable = false)
    private ScanSession session;

    @Column(name = "page_number")
    private int pageNumber;

    @Column(name = "decoded_url", columnDefinition = "TEXT")
    private String decodedUrl;

    @Column(name = "threat_score")
    private int threatScore;

    @Column(length = 20)
    private String verdict;

    @Column(name = "domain_age_days")
    private Integer domainAgeDays;

    @Column(name = "ssl_valid")
    private Boolean sslValid;

    @Column(name = "gsb_result", length = 30)
    private String gsbResult;

    @Column(name = "virustotal_summary", length = 100)
    private String virusTotalSummary;

    // JSONB column — Hibernate 6 handles List<String> ↔ JSON natively
    // Stores as: ["SUSPICIOUS_TLD", "HIGH_ENTROPY", "SHORT_DOMAIN_AGE"]
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "static_flags", columnDefinition = "jsonb")
    private List<String> staticFlags;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    public void prePersist() {
        this.createdAt = Instant.now();
    }
}