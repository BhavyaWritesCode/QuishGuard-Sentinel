-- QuishGuard Sentinel — V1 Initial Schema


-- ─── Users 
CREATE TABLE users (
    id              UUID            PRIMARY KEY,
    email           VARCHAR(255)    NOT NULL UNIQUE,
    password_hash   VARCHAR(255)    NOT NULL,
    role            VARCHAR(50)     NOT NULL DEFAULT 'USER',
    created_at      TIMESTAMP       NOT NULL DEFAULT NOW()
);

-- ─── Scan Sessions 
-- user_id is nullable — anonymous scans have no user
CREATE TABLE scan_sessions (
    id                  UUID            PRIMARY KEY,
    user_id             UUID            REFERENCES users(id),
    filename_original   VARCHAR(500),
    file_type           VARCHAR(20),
    pages_scanned       INTEGER,
    qr_count            INTEGER,
    overall_verdict     VARCHAR(20),
    created_at          TIMESTAMP       NOT NULL DEFAULT NOW()
);

-- ─── QR Results 
-- One row per QR code found — a PDF with 3 QR codes = 3 rows
CREATE TABLE qr_results (
    id                  UUID            PRIMARY KEY,
    session_id          UUID            NOT NULL REFERENCES scan_sessions(id),
    page_number         INTEGER,
    decoded_url         TEXT,
    threat_score        INTEGER,
    verdict             VARCHAR(20),
    domain_age_days     INTEGER,
    ssl_valid           BOOLEAN,
    gsb_result          VARCHAR(30),
    virustotal_summary  VARCHAR(100),
    static_flags        JSONB,
    created_at          TIMESTAMP       NOT NULL DEFAULT NOW()
);

-- ─── URL Analysis Cache 
-- Prevents duplicate VirusTotal/GSB API calls for same URL
-- PK is SHA-256 hash of the URL — not a UUID
CREATE TABLE url_analysis_cache (
    url_hash    VARCHAR(64)     PRIMARY KEY,
    url         TEXT,
    vt_result   JSONB,
    gsb_result  JSONB,
    cached_at   TIMESTAMP,
    expires_at  TIMESTAMP
);

-- ─── Indexes 
CREATE INDEX idx_scan_sessions_user_id   ON scan_sessions(user_id);
CREATE INDEX idx_scan_sessions_created   ON scan_sessions(created_at DESC);
CREATE INDEX idx_qr_results_session_id   ON qr_results(session_id);
CREATE INDEX idx_url_cache_expires_at    ON url_analysis_cache(expires_at);