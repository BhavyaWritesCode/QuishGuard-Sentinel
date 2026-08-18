package com.quishguard.sentinel.dto;

import java.util.List;
import java.util.UUID;

public record ScanResultDto(

        UUID sessionId,
        String verdict,
        int qrCount,
        int pagesScanned,
        long scanDurationMs,
        List<QrResultDto> results

) {}