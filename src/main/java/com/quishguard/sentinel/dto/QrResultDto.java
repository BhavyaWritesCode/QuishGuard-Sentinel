package com.quishguard.sentinel.dto;

import java.util.List;

public record QrResultDto(

        String decodedUrl,
        int threatScore,
        String verdict,
        Integer domainAgeDays,
        boolean sslValid,
        String gsbResult,
        String virusTotalSummary,
        List<String> staticFlags

) {}