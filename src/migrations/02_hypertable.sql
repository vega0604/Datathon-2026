-- SHE-72: Signals hypertable partitioned by month
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

CREATE TABLE IF NOT EXISTS exploit_signals (
    snapshot_month TIMESTAMPTZ NOT NULL,
    cve_id VARCHAR(32) NOT NULL,
    epss FLOAT,
    epss_pct FLOAT,
    in_kev SMALLINT DEFAULT 0,
    exploitdb SMALLINT DEFAULT 0,
    metasploit SMALLINT DEFAULT 0,
    nuclei SMALLINT DEFAULT 0,
    poc_github SMALLINT DEFAULT 0,
    PRIMARY KEY (cve_id, snapshot_month)
);

SELECT create_hypertable('exploit_signals', 'snapshot_month', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS idx_signals_cve_time ON exploit_signals (cve_id, snapshot_month DESC);
CREATE INDEX IF NOT EXISTS idx_signals_cve ON exploit_signals (cve_id);