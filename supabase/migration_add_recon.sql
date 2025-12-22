-- AETHER Migration: Add Recon Support
-- Run this in the Supabase SQL Editor if you already have the base schema

-- ============================================================================
-- STEP 1: Add scan_type enum if it doesn't exist
-- ============================================================================
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scan_type') THEN
        CREATE TYPE scan_type AS ENUM ('enumeration', 'recon');
    END IF;
END $$;

-- ============================================================================
-- STEP 2: Add new columns to scans table
-- ============================================================================
DO $$
BEGIN
    -- Add scan_type column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'scans' AND column_name = 'scan_type') THEN
        ALTER TABLE scans ADD COLUMN scan_type scan_type DEFAULT 'enumeration';
    END IF;
    
    -- Add parameters column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'scans' AND column_name = 'parameters') THEN
        ALTER TABLE scans ADD COLUMN parameters JSONB DEFAULT '{}';
    END IF;
END $$;

-- ============================================================================
-- STEP 3: Create recon_log_type enum
-- ============================================================================
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'recon_log_type') THEN
        CREATE TYPE recon_log_type AS ENUM ('info', 'success', 'warning', 'error');
    END IF;
END $$;

-- ============================================================================
-- STEP 4: Create finding_status enum
-- ============================================================================
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'finding_status') THEN
        CREATE TYPE finding_status AS ENUM ('open', 'resolved', 'informational', 'fixed', 'false-positive');
    END IF;
END $$;

-- ============================================================================
-- STEP 5: Create recon_logs table
-- ============================================================================
CREATE TABLE IF NOT EXISTS recon_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE NOT NULL,
    tool TEXT NOT NULL,
    log_type recon_log_type NOT NULL DEFAULT 'info',
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create index for recon_logs
CREATE INDEX IF NOT EXISTS idx_recon_logs_scan_id ON recon_logs(scan_id);
CREATE INDEX IF NOT EXISTS idx_recon_logs_created_at ON recon_logs(created_at);

-- ============================================================================
-- STEP 6: Create recon_findings table
-- ============================================================================
CREATE TABLE IF NOT EXISTS recon_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE NOT NULL,
    tool TEXT NOT NULL,
    severity severity_level NOT NULL DEFAULT 'info',
    name TEXT NOT NULL,
    description TEXT,
    endpoint TEXT,
    status finding_status DEFAULT 'open',
    raw_data TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for recon_findings
CREATE INDEX IF NOT EXISTS idx_recon_findings_scan_id ON recon_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_recon_findings_severity ON recon_findings(severity);

-- ============================================================================
-- STEP 7: Create recon_results table
-- ============================================================================
CREATE TABLE IF NOT EXISTS recon_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE NOT NULL,
    tool TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('success', 'error')),
    execution_time TEXT,
    parameters JSONB DEFAULT '{}',
    raw_output TEXT,
    parsed_results JSONB DEFAULT '{}',
    errors TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create index for recon_results
CREATE INDEX IF NOT EXISTS idx_recon_results_scan_id ON recon_results(scan_id);

-- ============================================================================
-- STEP 8: Enable RLS on new tables
-- ============================================================================
ALTER TABLE recon_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE recon_results ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- STEP 9: Create RLS policies for new tables (allow all for now)
-- ============================================================================
-- recon_logs policies
DROP POLICY IF EXISTS "Allow all on recon_logs" ON recon_logs;
CREATE POLICY "Allow all on recon_logs" ON recon_logs FOR ALL USING (true) WITH CHECK (true);

-- recon_findings policies
DROP POLICY IF EXISTS "Allow all on recon_findings" ON recon_findings;
CREATE POLICY "Allow all on recon_findings" ON recon_findings FOR ALL USING (true) WITH CHECK (true);

-- recon_results policies
DROP POLICY IF EXISTS "Allow all on recon_results" ON recon_results;
CREATE POLICY "Allow all on recon_results" ON recon_results FOR ALL USING (true) WITH CHECK (true);

-- ============================================================================
-- STEP 10: Create index on scan_type for faster queries
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_scans_scan_type ON scans(scan_type);

-- ============================================================================
-- Done! Your database now supports recon scans.
-- ============================================================================
SELECT 'Migration completed successfully!' as status;
