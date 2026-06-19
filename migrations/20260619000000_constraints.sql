DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'scans_status_check'
    ) THEN
        ALTER TABLE scans
        ADD CONSTRAINT scans_status_check
        CHECK (status IN ('running', 'completed', 'failed'));
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'findings_severity_check'
    ) THEN
        ALTER TABLE findings
        ADD CONSTRAINT findings_severity_check
        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_scans_status_created_at ON scans(status, created_at DESC);
