-- SHE-71: Core tables for vulnerabilities, KEV, scoreboard, and Granite extractions
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id VARCHAR(32) PRIMARY KEY,
    published DATE NOT NULL,
    cwe_ids VARCHAR(255),
    description TEXT
);

CREATE TABLE IF NOT EXISTS known_exploited (
    cve_id VARCHAR(32) PRIMARY KEY,
    vendor VARCHAR(128),
    product VARCHAR(128),
    date_added DATE NOT NULL,
    short_description TEXT
);

CREATE TABLE IF NOT EXISTS scoreboard (
    cve_id VARCHAR(32) PRIMARY KEY,
    published DATE NOT NULL,
    snapshot_month VARCHAR(7) NOT NULL,
    epss FLOAT,
    exploitdb SMALLINT DEFAULT 0,
    metasploit SMALLINT DEFAULT 0,
    nuclei SMALLINT DEFAULT 0,
    poc_github SMALLINT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS granite_extraction (
    cve_id VARCHAR(32) PRIMARY KEY,
    vendor VARCHAR(128),
    product VARCHAR(128),
    product_type VARCHAR(64),
    internet_facing BOOLEAN,
    auth_required BOOLEAN,
    impact VARCHAR(64)
);