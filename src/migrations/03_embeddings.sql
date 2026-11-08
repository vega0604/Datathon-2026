-- SHE-73: Embeddings table with pgvector HNSW index
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS cve_embeddings (
    cve_id VARCHAR(32) PRIMARY KEY,
    embedding vector(384) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_embeddings_hnsw 
ON cve_embeddings USING hnsw (embedding vector_cosine_ops);