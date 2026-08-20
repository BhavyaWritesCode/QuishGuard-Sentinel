package com.quishguard.sentinel.analysis;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class StaticAnalysisService {

    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            ".xyz", ".tk", ".top", ".club", ".work", ".gq", ".ml", ".ga", ".cf"
    );

    private static final Set<String> PHISHING_KEYWORDS = Set.of(
            "login", "verify", "secure", "account", "update",
            "banking", "signin", "password", "confirm", "suspend"
    );

    private static final Set<String> KNOWN_BRANDS = Set.of(
            "paypal", "google", "apple", "amazon", "microsoft",
            "facebook", "instagram", "netflix", "bank"
    );

    private static final Pattern IP_PATTERN =
            Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");

    private static final Pattern PUNYCODE_PATTERN =
            Pattern.compile("xn--");

    public List<String> analyze(String url) {
        List<String> flags = new ArrayList<>();

        try {
            URI uri = URI.create(url);
            String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase();
            String path = uri.getPath() == null ? "" : uri.getPath().toLowerCase();
            String query = uri.getQuery() == null ? "" : uri.getQuery().toLowerCase();
            String full = (path + " " + query).toLowerCase();

            checkSuspiciousTld(host, flags);
            checkIpAsHostname(host, flags);
            checkLookalikeDomain(host, flags);
            checkPunycode(host, flags);
            checkSubdomainDepth(host, flags);
            checkPhishingKeywords(full, flags);
            checkUrlLength(url, flags);
            checkUrlEntropy(host, flags);

        } catch (Exception e) {
            flags.add("UNPARSEABLE_URL");
        }

        return flags;
    }

    public int computeScore(List<String> flags) {
        int score = 0;
        for (String flag : flags) {
            score += switch (flag) {
                case "SUSPICIOUS_TLD"      -> 20;
                case "IP_AS_HOSTNAME"      -> 30;
                case "LOOKALIKE_DOMAIN"    -> 35;
                case "PUNYCODE_DOMAIN"     -> 25;
                case "EXCESSIVE_SUBDOMAINS"-> 15;
                case "PHISHING_KEYWORDS"   -> 20;
                case "HIGH_URL_ENTROPY"    -> 15;
                case "EXCESSIVE_URL_LENGTH"-> 10;
                case "UNPARSEABLE_URL"     -> 40;
                default                    -> 5;
            };
        }
        return Math.min(score, 100);
    }

    private void checkSuspiciousTld(String host, List<String> flags) {
        SUSPICIOUS_TLDS.stream()
                .filter(host::endsWith)
                .findFirst()
                .ifPresent(t -> flags.add("SUSPICIOUS_TLD"));
    }

    private void checkIpAsHostname(String host, List<String> flags) {
        if (IP_PATTERN.matcher(host).matches()) {
            flags.add("IP_AS_HOSTNAME");
        }
    }

    private void checkLookalikeDomain(String host, List<String> flags) {
        String normalized = host.replaceAll("[0-9]", "");
        for (String brand : KNOWN_BRANDS) {
            if (normalized.contains(brand) && !host.equals(brand + ".com")) {
                flags.add("LOOKALIKE_DOMAIN");
                return;
            }
        }
    }

    private void checkPunycode(String host, List<String> flags) {
        if (PUNYCODE_PATTERN.matcher(host).find()) {
            flags.add("PUNYCODE_DOMAIN");
        }
    }

    private void checkSubdomainDepth(String host, List<String> flags) {
        long depth = host.chars().filter(c -> c == '.').count();
        if (depth > 3) {
            flags.add("EXCESSIVE_SUBDOMAINS");
        }
    }

    private void checkPhishingKeywords(String urlContent, List<String> flags) {
        PHISHING_KEYWORDS.stream()
                .filter(urlContent::contains)
                .findFirst()
                .ifPresent(k -> flags.add("PHISHING_KEYWORDS"));
    }

    private void checkUrlLength(String url, List<String> flags) {
        if (url.length() > 150) {
            flags.add("EXCESSIVE_URL_LENGTH");
        }
    }

    private void checkUrlEntropy(String host, List<String> flags) {
        if (host.length() > 20) {
            long uniqueChars = host.chars().distinct().count();
            double ratio = (double) uniqueChars / host.length();
            if (ratio > 0.7) {
                flags.add("HIGH_URL_ENTROPY");
            }
        }
    }
}