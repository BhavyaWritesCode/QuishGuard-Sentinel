package com.quishguard.sentinel.controller;

import com.quishguard.sentinel.dto.ScanHistoryDto;
import com.quishguard.sentinel.dto.ScanResultDto;
import com.quishguard.sentinel.entity.ScanSession;
import com.quishguard.sentinel.repository.ScanSessionRepository;
import com.quishguard.sentinel.repository.UserRepository;
import com.quishguard.sentinel.service.ScanService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/scan")
public class ScanController {

    private final ScanService scanService;
    private final ScanSessionRepository scanSessionRepository;
    private final UserRepository userRepository;

    public ScanController(ScanService scanService,
                          ScanSessionRepository scanSessionRepository,
                          UserRepository userRepository) {
        this.scanService            = scanService;
        this.scanSessionRepository  = scanSessionRepository;
        this.userRepository         = userRepository;
    }

    @PostMapping("/upload")
    public ResponseEntity<ScanResultDto> upload(
            @RequestParam("file") MultipartFile file,
            @AuthenticationPrincipal UserDetails userDetails) {

        String email = userDetails != null ? userDetails.getUsername() : null;
        return ResponseEntity.ok(scanService.scan(file, email));
    }

    @GetMapping("/history")
    public ResponseEntity<List<ScanHistoryDto>> history(
            @AuthenticationPrincipal UserDetails userDetails) {

        return userRepository.findByEmail(userDetails.getUsername())
                .map(user -> {
                    List<ScanHistoryDto> history = scanSessionRepository
                            .findTop5ByUserIdOrderByCreatedAtDesc(user.getId())
                            .stream()
                            .map(this::toHistoryDto)
                            .toList();
                    return ResponseEntity.ok(history);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{sessionId}")
    public ResponseEntity<ScanResultDto> getResult(
            @PathVariable UUID sessionId,
            @AuthenticationPrincipal UserDetails userDetails) {

        return scanSessionRepository.findById(sessionId)
                .map(session -> ResponseEntity.ok(scanService.getResult(sessionId)))
                .orElse(ResponseEntity.notFound().build());
    }

    private ScanHistoryDto toHistoryDto(ScanSession session) {
        return new ScanHistoryDto(
                session.getId(),
                session.getFilenameOriginal(),
                session.getFileType(),
                session.getPagesScanned(),
                session.getQrCount(),
                session.getOverallVerdict(),
                session.getCreatedAt()
        );
    }
}