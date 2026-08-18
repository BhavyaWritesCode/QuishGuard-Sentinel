package com.quishguard.sentinel.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "scan_sessions")
@Getter
@Setter
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class ScanSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Nullable — anonymous scans have no user
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "filename_original", length = 500)
    private String filenameOriginal;

    @Column(name = "file_type", length = 20)
    private String fileType;

    @Column(name = "pages_scanned")
    private int pagesScanned;

    @Column(name = "qr_count")
    private int qrCount;

    @Column(name = "overall_verdict", length = 20)
    private String overallVerdict;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    public void prePersist() {
        this.createdAt = Instant.now();
    }
}