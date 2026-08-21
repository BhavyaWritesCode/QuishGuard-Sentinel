package com.quishguard.sentinel.service;

import com.quishguard.sentinel.analysis.ExternalThreatService;
import com.quishguard.sentinel.analysis.StaticAnalysisService;
import com.quishguard.sentinel.dto.QrResultDto;
import com.quishguard.sentinel.dto.ScanResultDto;
import com.quishguard.sentinel.entity.QrResult;
import com.quishguard.sentinel.entity.ScanSession;
import com.quishguard.sentinel.entity.User;
import com.quishguard.sentinel.pipeline.QrPipelineService;
import com.quishguard.sentinel.repository.QrResultRepository;
import com.quishguard.sentinel.repository.ScanSessionRepository;
import com.quishguard.sentinel.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final FileValidationService fileValidationService;
    private final QrPipelineService qrPipelineService;
    private final StaticAnalysisService staticAnalysisService;
    private final ExternalThreatService externalThreatService;
    private final ScanSessionRepository scanSessionRepository;
    private final QrResultRepository qrResultRepository;
    private final UserRepository userRepository;

    public ScanService(FileValidationService fileValidationService,
                       QrPipelineService qrPipelineService,
                       StaticAnalysisService staticAnalysisService,
                       ExternalThreatService externalThreatService,
                       ScanSessionRepository scanSessionRepository,
                       QrResultRepository qrResultRepository,
                       UserRepository userRepository) {
        this.fileValidationService  = fileValidationService;
        this.qrPipelineService      = qrPipelineService;
        this.staticAnalysisService  = staticAnalysisService;
        this.externalThreatService  = externalThreatService;
        this.scanSessionRepository  = scanSessionRepository;
        this.qrResultRepository     = qrResultRepository;
        this.userRepository         = userRepository;
    }

    public ScanResultDto scan(MultipartFile file, String userEmail) {
        long startTime = System.currentTimeMillis();

        boolean isAuthenticated = userEmail != null;
        FileValidationService.FileType fileType =
                fileValidationService.validateAndClassify(file, isAuthenticated);

        Optional<User> user = isAuthenticated
                ? userRepository.findByEmail(userEmail)
                : Optional.empty();

        ScanSession session = ScanSession.builder()
                .user(user.orElse(null))
                .filenameOriginal(file.getOriginalFilename())
                .fileType(fileType.name())
                .build();

        session = scanSessionRepository.save(session);

        List<String> urls;
        try {
            urls = qrPipelineService.extractUrls(file.getInputStream());
        } catch (Exception e) {
            log.error("QR extraction failed", e);
            urls = List.of();
        }

        List<QrResultDto> qrResults = new ArrayList<>();

        for (String url : urls) {
            List<String> flags = staticAnalysisService.analyze(url);
            int score = staticAnalysisService.computeScore(flags);

            ExternalThreatService.ExternalThreatResult external =
                    externalThreatService.analyze(url);

            score = Math.min(100, score + externalScoreBoost(external));

            String verdict = computeVerdict(score);

            QrResult qrResult = QrResult.builder()
                    .session(session)
                    .pageNumber(1)
                    .decodedUrl(url)
                    .threatScore(score)
                    .verdict(verdict)
                    .domainAgeDays(external.domainAgeDays() == -1
                            ? null : external.domainAgeDays())
                    .gsbResult(external.gsbResult())
                    .virusTotalSummary(external.virusTotalSummary())
                    .staticFlags(flags)
                    .build();

            qrResultRepository.save(qrResult);

            qrResults.add(new QrResultDto(
                    url, score, verdict,
                    external.domainAgeDays() == -1 ? null : external.domainAgeDays(),
                    false,
                    external.gsbResult(),
                    external.virusTotalSummary(),
                    flags
            ));
        }

        String overallVerdict = qrResults.isEmpty() ? "SAFE" :
                qrResults.stream()
                        .map(QrResultDto::verdict)
                        .reduce("SAFE", this::worstVerdict);

        session.setQrCount(qrResults.size());
        session.setPagesScanned(1);
        session.setOverallVerdict(overallVerdict);
        scanSessionRepository.save(session);

        long duration = System.currentTimeMillis() - startTime;

        return new ScanResultDto(
                session.getId(),
                overallVerdict,
                qrResults.size(),
                1,
                duration,
                qrResults
        );
    }

    public ScanResultDto getResult(UUID sessionId) {
        ScanSession session = scanSessionRepository.findById(sessionId)
                .orElseThrow(() -> new RuntimeException("Session not found"));

        List<QrResultDto> results = qrResultRepository.findBySessionId(sessionId)
                .stream()
                .map(qr -> new QrResultDto(
                        qr.getDecodedUrl(),
                        qr.getThreatScore(),
                        qr.getVerdict(),
                        qr.getDomainAgeDays(),
                        qr.getSslValid() != null && qr.getSslValid(),
                        qr.getGsbResult(),
                        qr.getVirusTotalSummary(),
                        qr.getStaticFlags()
                ))
                .toList();

        return new ScanResultDto(
                session.getId(),
                session.getOverallVerdict(),
                session.getQrCount(),
                session.getPagesScanned(),
                0,
                results
        );
    }

    private int externalScoreBoost(ExternalThreatService.ExternalThreatResult result) {
        int boost = 0;
        if ("MALICIOUS".equals(result.gsbResult())) boost += 50;
        if (result.domainAgeDays() != -1 && result.domainAgeDays() < 30) boost += 25;
        return boost;
    }

    private String computeVerdict(int score) {
        if (score >= 70) return "DANGEROUS";
        if (score >= 35) return "SUSPICIOUS";
        return "SAFE";
    }

    private String worstVerdict(String a, String b) {
        if ("DANGEROUS".equals(a) || "DANGEROUS".equals(b)) return "DANGEROUS";
        if ("SUSPICIOUS".equals(a) || "SUSPICIOUS".equals(b)) return "SUSPICIOUS";
        return "SAFE";
    }
}