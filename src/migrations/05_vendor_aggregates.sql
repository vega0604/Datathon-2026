-- SHE-76: Monthly Vendor Activity Aggregate
-- Tracks monthly KEV additions and exploit-code appearances per normalized vendor per month

CREATE MATERIALIZED VIEW IF NOT EXISTS vendor_monthly_activity AS
WITH monthly_kev AS (
    SELECT 
        LOWER(TRIM(vendor)) AS vendor,
        date_trunc('month', date_added::timestamptz) AS activity_month,
        COUNT(DISTINCT cve_id) AS kev_additions
    FROM known_exploited
    WHERE vendor IS NOT NULL AND TRIM(vendor) != ''
    GROUP BY LOWER(TRIM(vendor)), date_trunc('month', date_added::timestamptz)
),
monthly_signals AS (
    SELECT 
        LOWER(TRIM(k.vendor)) AS vendor,
        date_trunc('month', s.snapshot_month) AS activity_month,
        COUNT(DISTINCT s.cve_id) AS monitored_cves,
        SUM(CASE WHEN s.exploitdb > 0 OR s.metasploit > 0 OR s.nuclei > 0 OR s.poc_github > 0 THEN 1 ELSE 0 END) AS cves_with_exploit_code,
        SUM(s.exploitdb) AS total_exploitdb_hits,
        SUM(s.metasploit) AS total_metasploit_hits,
        SUM(s.nuclei) AS total_nuclei_hits,
        SUM(s.poc_github) AS total_poc_github_hits,
        AVG(s.epss) AS avg_epss
    FROM exploit_signals s
    JOIN known_exploited k ON s.cve_id = k.cve_id
    WHERE k.vendor IS NOT NULL AND TRIM(k.vendor) != ''
    GROUP BY LOWER(TRIM(k.vendor)), date_trunc('month', s.snapshot_month)
)
SELECT 
    COALESCE(k.vendor, s.vendor) AS vendor,
    COALESCE(k.activity_month, s.activity_month) AS activity_month,
    COALESCE(k.kev_additions, 0) AS kev_additions,
    COALESCE(s.monitored_cves, 0) AS monitored_cves,
    COALESCE(s.cves_with_exploit_code, 0) AS cves_with_exploit_code,
    COALESCE(s.total_exploitdb_hits, 0) AS total_exploitdb_hits,
    COALESCE(s.total_metasploit_hits, 0) AS total_metasploit_hits,
    COALESCE(s.total_nuclei_hits, 0) AS total_nuclei_hits,
    COALESCE(s.total_poc_github_hits, 0) AS total_poc_github_hits,
    ROUND(COALESCE(s.avg_epss, 0)::numeric, 4) AS avg_epss
FROM monthly_kev k
FULL OUTER JOIN monthly_signals s 
    ON k.vendor = s.vendor AND k.activity_month = s.activity_month;

-- Unique index required for REFRESH MATERIALIZED VIEW CONCURRENTLY
CREATE UNIQUE INDEX IF NOT EXISTS idx_vendor_monthly_activity_unique 
ON vendor_monthly_activity (vendor, activity_month);

CREATE INDEX IF NOT EXISTS idx_vendor_monthly_activity_month 
ON vendor_monthly_activity (activity_month DESC);
