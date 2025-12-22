-- AETHER Database Schema for Supabase
-- Run this in the Supabase SQL Editor

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create enum types
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');

-- Create scans table
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_url TEXT NOT NULL,
    status scan_status DEFAULT 'pending',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    config JSONB DEFAULT '{}',
    stats JSONB,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL
);

-- Create vulnerabilities table
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    severity severity_level NOT NULL,
    confidence DECIMAL(3, 2) CHECK (confidence >= 0 AND confidence <= 1),
    owasp_category TEXT NOT NULL,
    cwe_id TEXT,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    parameter TEXT,
    evidence TEXT,
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    request_sample TEXT,
    response_sample TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for better query performance
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to scans table
CREATE TRIGGER update_scans_updated_at
    BEFORE UPDATE ON scans
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Row Level Security (RLS) Policies
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view their own scans
CREATE POLICY "Users can view their own scans"
    ON scans FOR SELECT
    USING (auth.uid() = user_id OR user_id IS NULL);

-- Policy: Users can insert their own scans
CREATE POLICY "Users can insert their own scans"
    ON scans FOR INSERT
    WITH CHECK (auth.uid() = user_id OR user_id IS NULL);

-- Policy: Users can update their own scans
CREATE POLICY "Users can update their own scans"
    ON scans FOR UPDATE
    USING (auth.uid() = user_id OR user_id IS NULL);

-- Policy: Users can delete their own scans
CREATE POLICY "Users can delete their own scans"
    ON scans FOR DELETE
    USING (auth.uid() = user_id OR user_id IS NULL);

-- Policy: Users can view vulnerabilities for their scans
CREATE POLICY "Users can view vulnerabilities for their scans"
    ON vulnerabilities FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM scans
            WHERE scans.id = vulnerabilities.scan_id
            AND (scans.user_id = auth.uid() OR scans.user_id IS NULL)
        )
    );

-- Policy: Users can insert vulnerabilities for their scans
CREATE POLICY "Users can insert vulnerabilities for their scans"
    ON vulnerabilities FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM scans
            WHERE scans.id = vulnerabilities.scan_id
            AND (scans.user_id = auth.uid() OR scans.user_id IS NULL)
        )
    );

-- Anonymous access for development (optional - remove in production)
CREATE POLICY "Allow anonymous access to scans"
    ON scans FOR ALL
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Allow anonymous access to vulnerabilities"
    ON vulnerabilities FOR ALL
    USING (true)
    WITH CHECK (true);

-- Create a view for scan summaries
CREATE OR REPLACE VIEW scan_summaries AS
SELECT 
    s.id,
    s.target_url,
    s.status,
    s.created_at,
    s.completed_at,
    s.config,
    COALESCE(s.stats, '{}')::jsonb as stats,
    COUNT(v.id) as vulnerability_count,
    COUNT(CASE WHEN v.severity = 'critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN v.severity = 'high' THEN 1 END) as high_count,
    COUNT(CASE WHEN v.severity = 'medium' THEN 1 END) as medium_count,
    COUNT(CASE WHEN v.severity = 'low' THEN 1 END) as low_count
FROM scans s
LEFT JOIN vulnerabilities v ON v.scan_id = s.id
GROUP BY s.id;
