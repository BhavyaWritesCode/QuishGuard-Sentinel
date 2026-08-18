package com.quishguard.sentinel.dto;

public record AuthResponseDto(

        String accessToken,
        String refreshToken,
        String tokenType

) {
    // Convenience factory — always sets tokenType to "Bearer"
    public static AuthResponseDto of(String accessToken, String refreshToken) {
        return new AuthResponseDto(accessToken, refreshToken, "Bearer");
    }
}