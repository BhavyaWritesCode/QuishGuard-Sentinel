package com.quishguard.desktop.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.quishguard.desktop.util.HashUtil;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import java.net.URI;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Base64;
import java.util.logging.Logger;

public class ExternalThreatService {

    private static final Logger log = Logger.getLogger(ExternalThreatService.class.getName());
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final OkHttpClient httpClient = new OkHttpClient();

    private static final String GSB_URL =
            "https://safebrowsing.googleapis.com/v4/threatMatches:find";
    private static final long CACHE_TTL_SECONDS = 86400; // 24 hours

    private final String vtKey;
    private final String gsbKey;
    private final Connection dbConnection;

    public ExternalThreatService(String vtKey, String gsbKey, Connection dbConnection) {
        this.vtKey        = vtKey;
        this.gsbKey       = gsbKey;
        this.dbConnection = dbConnection;
    }

    public ExternalThreatResult analyze(String url) {
        String urlHash = HashUtil.sha256(url);

        // Check SQLite cache first
        ExternalThreatResult cached = checkCache(urlHash);
        if (cached != null) {
            log.info("Cache hit for: " + urlHash);
            return cached;
        }

        String gsbResult = checkGoogleSafeBrowsing(url);
        String vtResult  = checkVirusTotal(url);
        int domainAge    = checkDomainAge(url);

        saveToCache(urlHash, url, gsbResult, vtResult, domainAge);

        return new ExternalThreatResult(gsbResult, vtResult, domainAge);
    }

    private String checkGoogleSafeBrowsing(String url) {
        if (gsbKey == null || gsbKey.isBlank()) return "GSB_UNAVAILABLE";
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

            Request request = new Request.Builder()
                    .url(GSB_URL + "?key=" + gsbKey)
                    .post(RequestBody.create(body, MediaType.parse("application/json")))
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.body() != null) {
                    JsonNode json = mapper.readTree(response.body().string());
                    if (json.has("matches")) return "MALICIOUS";
                }
            }
            return "CLEAN";
        } catch (Exception e) {
            log.warning("GSB check failed: " + e.getMessage());
            return "GSB_UNAVAILABLE";
        }
    }

    private String checkVirusTotal(String url) {
        if (vtKey == null || vtKey.isBlank()) return "VT_UNAVAILABLE";
        try {
            String urlId = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(url.getBytes());

            Request request = new Request.Builder()
                    .url("https://www.virustotal.com/api/v3/urls/" + urlId)
                    .header("x-apikey", vtKey)
                    .get()
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.body() != null) {
                    JsonNode json = mapper.readTree(response.body().string());
                    JsonNode stats = json.path("data")
                            .path("attributes")
                            .path("last_analysis_stats");

                    int malicious  = stats.path("malicious").asInt(0);
                    int suspicious = stats.path("suspicious").asInt(0);
                    int total      = malicious + suspicious
                            + stats.path("harmless").asInt(0)
                            + stats.path("undetected").asInt(0);

                    return (malicious + suspicious) + "/" + total + " scanners flagged";
                }
            }
            return "VT_UNAVAILABLE";
        } catch (Exception e) {
            log.warning("VirusTotal check failed: " + e.getMessage());
            return "VT_UNAVAILABLE";
        }
    }

    private int checkDomainAge(String url) {
        try {
            String host = URI.create(url).getHost();
            if (host == null) return -1;

            Request request = new Request.Builder()
                    .url("https://rdap.org/domain/" + host)
                    .get()
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.body() != null) {
                    JsonNode json = mapper.readTree(response.body().string());
                    if (json.has("events")) {
                        for (JsonNode event : json.get("events")) {
                            if ("registration".equals(event.path("eventAction").asText())) {
                                Instant registered = Instant.parse(
                                        event.path("eventDate").asText());
                                return (int) ((Instant.now().toEpochMilli()
                                        - registered.toEpochMilli()) / 86400000);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.warning("RDAP check failed: " + e.getMessage());
        }
        return -1;
    }

    private ExternalThreatResult checkCache(String urlHash) {
        try {
            String sql = "SELECT gsb_result, vt_result, domain_age_days FROM url_cache " +
                         "WHERE url_hash = ? AND expires_at > ?";
            PreparedStatement stmt = dbConnection.prepareStatement(sql);
            stmt.setString(1, urlHash);
            stmt.setLong(2, Instant.now().getEpochSecond());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new ExternalThreatResult(
                        rs.getString("gsb_result"),
                        rs.getString("vt_result"),
                        rs.getInt("domain_age_days")
                );
            }
        } catch (SQLException e) {
            log.warning("Cache read failed: " + e.getMessage());
        }
        return null;
    }

    private void saveToCache(String urlHash, String url,
                             String gsbResult, String vtResult, int domainAge) {
        try {
            String sql = "INSERT OR REPLACE INTO url_cache " +
                         "(url_hash, url, gsb_result, vt_result, domain_age_days, " +
                         "cached_at, expires_at) VALUES (?,?,?,?,?,?,?)";
            PreparedStatement stmt = dbConnection.prepareStatement(sql);
            long now = Instant.now().getEpochSecond();
            stmt.setString(1, urlHash);
            stmt.setString(2, url);
            stmt.setString(3, gsbResult);
            stmt.setString(4, vtResult);
            stmt.setInt(5, domainAge);
            stmt.setLong(6, now);
            stmt.setLong(7, now + CACHE_TTL_SECONDS);
            stmt.executeUpdate();
        } catch (SQLException e) {
            log.warning("Cache save failed: " + e.getMessage());
        }
    }

    public record ExternalThreatResult(
            String gsbResult,
            String virusTotalSummary,
            int domainAgeDays
    ) {}
}