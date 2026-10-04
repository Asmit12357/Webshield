-- Reference schema. app.py creates and migrates this table automatically.
CREATE TABLE scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    score INTEGER NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    grade TEXT,                                   -- A+ .. F
    details TEXT,                                 -- JSON list of check results
    score_version INTEGER NOT NULL DEFAULT 1      -- 1 = legacy presence-only scoring, 2 = current
);
