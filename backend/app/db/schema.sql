-- SignalTrace Database Schema

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    filename TEXT NOT NULL,
    num_lines INTEGER NOT NULL,
    num_incidents INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    rank INTEGER NOT NULL,
    signature TEXT NOT NULL,
    score REAL NOT NULL,
    priority TEXT NOT NULL DEFAULT 'P3',
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    count INTEGER NOT NULL,
    services_json TEXT NOT NULL,
    first_seen TEXT,
    last_seen TEXT,
    stats_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    explanation_json TEXT NOT NULL,
    used_llm INTEGER NOT NULL DEFAULT 0,
    validation_errors_json TEXT,
    FOREIGN KEY (run_id) REFERENCES runs (run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_incidents_run_id ON incidents(run_id);
CREATE INDEX IF NOT EXISTS idx_incidents_rank ON incidents(run_id, rank);
CREATE INDEX IF NOT EXISTS idx_runs_created_at ON runs(created_at DESC);

