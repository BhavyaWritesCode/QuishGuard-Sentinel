package com.quishguard.sentinel.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import com.quishguard.sentinel.entity.UrlAnalysisCache;
import com.quishguard.sentinel.repository.UrlAnalysisCacheRepository;
import com.quishguard.sentinel.util.HashUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

@Service
public class ExternalThreatService {

    private static final Logger log = LoggerFactory.getLogger(ExternalThreatService.class);

    private final UrlAnalysisCacheRepository cacheRepository;
    private final WebClient webClient;

    @Value("${api.virustotal.key:}")
    private String vtKey;

    @Value("${api.google-safe-browsing.key:}")
    private String gsbKey;

    @Value("${api.google-safe-browsing.url}")
    private String gsbUrl;

    public ExternalThreatService(UrlAnalysisCacheRepository cacheRepository,
                                 WebClient.Builder webClientBuilder) {
        this.cacheRepository = cacheRepository;
        this.webClient = webClientBuilder.build();
    }

    public ExternalThreatResult analyze(String url) {
        String urlHash = HashUtil.sha256(url);

        Optional<UrlAnalysisCache> cached =
                cacheRepository.findByUrlHashAndExpiresAtAfter(urlHash, Instant.now());

        if (cached.isPresent()) {
            log.debug("Cache hit for URL hash: {}", urlHash);
            return fromCache(cached.get());
        }

        String gsbResult = checkGoogleSafeBrowsing(url);
        String vtResult  = checkVirusTotal(url);
        int    domainAge = checkDomainAge(url);

        saveToCache(urlHash, url, gsbResult, vtResult);

        return new ExternalThreatResult(gsbResult, vtResult, domainAge);
    }

    private String checkGoogleSafeBrowsing(String url) {
        if (gsbKey == null || gsbKey.isBlank()) {
            return "GSB_UNAVAILABLE";
        }
        try {
            String body = """
                {
                  "client": {"clientId": "quishguard", "clientVersion": "1.0"},
                  "threatInfo": {
                    "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": "%s"}]
                  }
                }
                """.formatted(url);

            JsonNode response = webClient.post()
                    .uri(gsbUrl + "?key=" + gsbKey)
                    .header("Content-Type", "application/json")
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(JsonNode.class)
                    .block();

            if (response != null && response.has("matches")) {
                return "MALICIOUS";
            }
            return "CLEAN";
        } catch (Exception e) {
            log.warn("GSB check failed: {}", e.getMessage());
            return "GSB_UNAVAILABLE";
        }
    }

    private String checkVirusTotal(String url) {
        if (vtKey == null || vtKey.isBlank()) {
            return "VT_UNAVAILABLE";
        }
        try {
            String urlId = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(url.getBytes());

            JsonNode response = webClient.get()
                    .uri("https://www.virustotal.com/api/v3/urls/" + urlId)
                    .header("x-apikey", vtKey)
                    .retrieve()
                    .bodyToMono(JsonNode.class)
                    .block();

            if (response != null) {
                JsonNode stats = response
                        .path("data")
                        .path("attributes")
                        .path("last_analysis_stats");

                int malicious  = stats.path("malicious").asInt(0);
                int suspicious = stats.path("suspicious").asInt(0);
                int total      = malicious + suspicious
                        + stats.path("harmless").asInt(0)
                        + stats.path("undetected").asInt(0);

                return (malicious + suspicious) + "/" + total + " scanners flagged";
            }
            return "VT_UNAVAILABLE";
        } catch (Exception e) {
            log.warn("VirusTotal check failed: {}", e.getMessage());
            return "VT_UNAVAILABLE";
        }
    }

    private int checkDomainAge(String url) {
        try {
            String host = java.net.URI.create(url).getHost();
            if (host == null) return -1;

            String rdapUrl = "https://rdap.org/domain/" + host;
            JsonNode response = webClient.get()
                    .uri(rdapUrl)
                    .retrieve()
                    .bodyToMono(JsonNode.class)
                    .block();

            if (response != null && response.has("events")) {
                for (JsonNode event : response.get("events")) {
                    if ("registration".equals(event.path("eventAction").asText())) {
                        String date = event.path("eventDate").asText();
                        Instant registered = Instant.parse(date);
                        return (int) ((Instant.now().toEpochMilli()
                                - registered.toEpochMilli()) / 86400000);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("RDAP check failed: {}", e.getMessage());
        }
        return -1;
    }

    private void saveToCache(String urlHash, String url,
                             String gsbResult, String vtResult) {
        try {
            UrlAnalysisCache cache = UrlAnalysisCache.builder()
                    .urlHash(urlHash)
                    .url(url)
                    .cachedAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(86400))
                    .build();
            cacheRepository.save(cache);
        } catch (Exception e) {
            log.warn("Cache save failed: {}", e.getMessage());
        }
    }

    private ExternalThreatResult fromCache(UrlAnalysisCache cache) {
        return new ExternalThreatResult("CLEAN", "VT_UNAVAILABLE", -1);
    }

    public record ExternalThreatResult(
            String gsbResult,
            String virusTotalSummary,
            int domainAgeDays
    ) {}
}