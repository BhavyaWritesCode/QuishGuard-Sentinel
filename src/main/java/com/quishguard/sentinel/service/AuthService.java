package com.quishguard.sentinel.service;

import com.quishguard.sentinel.dto.AuthRequestDto;
import com.quishguard.sentinel.dto.AuthResponseDto;
import com.quishguard.sentinel.entity.User;
import com.quishguard.sentinel.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public AuthResponseDto register(AuthRequestDto request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new RuntimeException("Email already registered");
        }

        User user = User.builder()
                .email(request.email())
                .passwordHash(passwordEncoder.encode(request.password()))
                .role("USER")
                .build();

        userRepository.save(user);

        String accessToken  = jwtService.generateAccessToken(user.getEmail());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        return AuthResponseDto.of(accessToken, refreshToken);
    }

    public AuthResponseDto login(AuthRequestDto request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );

        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new RuntimeException("User not found"));

        String accessToken  = jwtService.generateAccessToken(user.getEmail());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        return AuthResponseDto.of(accessToken, refreshToken);
    }

    public AuthResponseDto refresh(String refreshToken) {
        String email = jwtService.extractEmail(refreshToken);

        if (jwtService.isTokenExpired(refreshToken)) {
            throw new RuntimeException("Refresh token expired");
        }

        String newAccessToken = jwtService.generateAccessToken(email);
        return AuthResponseDto.of(newAccessToken, refreshToken);
    }
}