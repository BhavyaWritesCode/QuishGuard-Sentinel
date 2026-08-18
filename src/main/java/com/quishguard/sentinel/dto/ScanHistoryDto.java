package com.quishguard.sentinel.dto;

import java.time.Instant;
import java.util.UUID;

public record ScanHistoryDto(

        UUID sessionId,
        String filenameOriginal,
        String fileType,
        int pagesScanned,
        int qrCount,
        String verdict,
        Instant createdAt

) {}