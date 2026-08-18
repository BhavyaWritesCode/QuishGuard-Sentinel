package com.quishguard.sentinel.dto;

import java.time.Instant;

public record ErrorResponseDto(

        String error,
        String message,
        int status,
        Instant timestamp

) {
    // Convenience factory — timestamp always set automatically
    public static ErrorResponseDto of(String error, String message, int status) {
        return new ErrorResponseDto(error, message, status, Instant.now());
    }
}   