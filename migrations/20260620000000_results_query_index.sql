CREATE INDEX IF NOT EXISTS idx_findings_scan_id_created_at
ON findings(scan_id, created_at DESC);
