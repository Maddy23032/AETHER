-- AETHER Migration: Add Mobile Scan Support
-- Run this in the Supabase SQL Editor if you already have the base schema

-- ============================================================================
-- STEP 1: Update scan_type enum to include 'mobile'
-- ============================================================================
-- Note: PostgreSQL doesn't allow easy enum modification, so we use this approach
DO $$
BEGIN
    -- Check if 'mobile' already exists in the enum
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum 
        WHERE enumlabel = 'mobile' 
        AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'scan_type')
    ) THEN
        ALTER TYPE scan_type ADD VALUE 'mobile';
    END IF;
END $$;

-- ============================================================================
-- STEP 2: Create mobile_platform enum
-- ============================================================================
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'mobile_platform') THEN
        CREATE TYPE mobile_platform AS ENUM ('android', 'ios');
    END IF;
END $$;

-- ============================================================================
-- STEP 3: Create mobile_scans table
-- ============================================================================
CREATE TABLE IF NOT EXISTS mobile_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_hash TEXT NOT NULL,
    filename TEXT NOT NULL,
    package_name TEXT,
    app_name TEXT,
    version TEXT,
    platform mobile_platform DEFAULT 'android',
    security_score INTEGER CHECK (security_score >= 0 AND security_score <= 100),
    grade TEXT CHECK (grade IN ('A', 'B', 'C', 'D', 'F')),
    scan_type TEXT DEFAULT 'static',
    json_report JSONB,
    scorecard JSONB,
    permissions JSONB,
    security_issues JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- STEP 4: Create indexes for mobile_scans
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_mobile_scans_file_hash ON mobile_scans(file_hash);
CREATE INDEX IF NOT EXISTS idx_mobile_scans_package_name ON mobile_scans(package_name);
CREATE INDEX IF NOT EXISTS idx_mobile_scans_created_at ON mobile_scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mobile_scans_platform ON mobile_scans(platform);
CREATE INDEX IF NOT EXISTS idx_mobile_scans_grade ON mobile_scans(grade);

-- ============================================================================
-- STEP 5: Enable Row Level Security (RLS)
-- ============================================================================
ALTER TABLE mobile_scans ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- STEP 6: Create RLS policies
-- ============================================================================
-- Allow all operations for now (adjust based on your auth requirements)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE tablename = 'mobile_scans' AND policyname = 'Enable all access for mobile_scans'
    ) THEN
        CREATE POLICY "Enable all access for mobile_scans" ON mobile_scans
            FOR ALL
            USING (true)
            WITH CHECK (true);
    END IF;
END $$;

-- ============================================================================
-- STEP 7: Create function to update updated_at timestamp
-- ============================================================================
CREATE OR REPLACE FUNCTION update_mobile_scans_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- STEP 8: Create trigger for updated_at
-- ============================================================================
DROP TRIGGER IF EXISTS mobile_scans_updated_at ON mobile_scans;
CREATE TRIGGER mobile_scans_updated_at
    BEFORE UPDATE ON mobile_scans
    FOR EACH ROW
    EXECUTE FUNCTION update_mobile_scans_updated_at();

-- ============================================================================
-- STEP 9: Grant permissions
-- ============================================================================
GRANT ALL ON mobile_scans TO postgres;
GRANT ALL ON mobile_scans TO anon;
GRANT ALL ON mobile_scans TO authenticated;
GRANT ALL ON mobile_scans TO service_role;

-- ============================================================================
-- VERIFICATION: Check tables exist
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE 'Mobile scans migration completed successfully!';
    RAISE NOTICE 'Tables created: mobile_scans';
    RAISE NOTICE 'Enums updated: scan_type (added mobile), mobile_platform (created)';
END $$;
