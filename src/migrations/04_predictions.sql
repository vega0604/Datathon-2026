-- SHE-74: Predictions table for ranked inference outputs and explanation narrative
CREATE TABLE IF NOT EXISTS predictions (
    cve_id VARCHAR(32) PRIMARY KEY,
    score FLOAT NOT NULL,
    rank INT NOT NULL,
    top_reasons TEXT,
    explanation TEXT
);

CREATE INDEX IF NOT EXISTS idx_predictions_rank ON predictions (rank ASC);