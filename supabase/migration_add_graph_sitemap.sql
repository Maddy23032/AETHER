-- =====================================================
-- AETHER Dynamic Graph Sitemap Schema
-- Migration: Add graph-based sitemap functionality
-- =====================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================================================
-- 1. Graph Sessions - One per target scan session
-- =====================================================
CREATE TABLE IF NOT EXISTS graph_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_url TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'completed', 'failed', 'archived')),
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    config JSONB DEFAULT '{
        "max_depth": 10,
        "include_subdomains": true,
        "include_external": false,
        "crawl_js": true
    }',
    stats JSONB DEFAULT '{
        "total_nodes": 0,
        "total_edges": 0,
        "total_vulnerabilities": 0,
        "max_depth_reached": 0
    }',
    metrics JSONB DEFAULT '{
        "attack_surface_score": 0,
        "avg_risk_score": 0,
        "critical_paths_count": 0
    }',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================
-- 2. Graph Nodes - Each discovered asset/endpoint
-- =====================================================
CREATE TYPE node_type AS ENUM (
    'domain',
    'subdomain', 
    'ip_address',
    'port',
    'endpoint',
    'parameter',
    'api_endpoint',
    'technology',
    'vulnerability',
    'auth_point',
    'form',
    'file',
    'external_service',
    'certificate',
    'cookie',
    'header'
);

CREATE TABLE IF NOT EXISTS graph_nodes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES graph_sessions(id) ON DELETE CASCADE,
    
    -- Node identification
    node_type node_type NOT NULL,
    label TEXT NOT NULL,
    url TEXT,
    url_hash TEXT,
    
    -- Discovery metadata
    depth INTEGER DEFAULT 0,
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    discovery_method TEXT DEFAULT 'crawl',
    parent_node_id UUID REFERENCES graph_nodes(id) ON DELETE SET NULL,
    scan_source TEXT, -- 'recon', 'enumeration', 'mobile', 'manual'
    
    -- HTTP response data (for endpoints)
    http_method TEXT DEFAULT 'GET',
    status_code INTEGER,
    content_type TEXT,
    content_length INTEGER,
    response_time_ms FLOAT,
    title TEXT,
    
    -- Security context
    auth_required BOOLEAN DEFAULT FALSE,
    auth_type TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,
    
    -- Parameters and data
    parameters JSONB DEFAULT '[]',
    headers JSONB DEFAULT '{}',
    cookies JSONB DEFAULT '[]',
    forms JSONB DEFAULT '[]',
    
    -- Technology fingerprinting
    technologies JSONB DEFAULT '[]',
    
    -- Clustering (AI-derived)
    cluster_id TEXT,
    cluster_label TEXT,
    
    -- Risk metrics
    risk_score FLOAT DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    vulnerability_count INTEGER DEFAULT 0,
    
    -- Graph metrics (computed)
    in_degree INTEGER DEFAULT 0,
    out_degree INTEGER DEFAULT 0,
    pagerank FLOAT DEFAULT 0,
    betweenness FLOAT DEFAULT 0,
    is_choke_point BOOLEAN DEFAULT FALSE,
    
    -- Visualization
    x_position FLOAT,
    y_position FLOAT,
    node_size FLOAT DEFAULT 20,
    node_color TEXT,
    is_expanded BOOLEAN DEFAULT TRUE,
    is_visible BOOLEAN DEFAULT TRUE,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    
    properties JSONB DEFAULT '{}',
    
    UNIQUE(session_id, url_hash, http_method)
);

-- =====================================================
-- 3. Graph Edges - Relationships between nodes
-- =====================================================
CREATE TYPE edge_type AS ENUM (
    'links_to',          -- href, anchor
    'redirects_to',      -- 3xx redirect
    'submits_to',        -- form action
    'calls_api',         -- AJAX/fetch
    'loads_resource',    -- script, css, image
    'has_subdomain',     -- domain -> subdomain
    'resolves_to',       -- domain -> IP
    'runs_service',      -- IP -> port
    'serves_endpoint',   -- service -> endpoint
    'accepts_parameter', -- endpoint -> parameter
    'has_vulnerability', -- node -> vulnerability
    'uses_technology',   -- node -> technology
    'authenticates_via', -- endpoint -> auth
    'sets_cookie',       -- endpoint -> cookie
    'includes_header',   -- endpoint -> header
    'contains_form',     -- endpoint -> form
    'data_flows_to',     -- data flow relationship
    'depends_on',        -- dependency relationship
    'external_call'      -- calls external service
);

CREATE TABLE IF NOT EXISTS graph_edges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES graph_sessions(id) ON DELETE CASCADE,
    
    source_node_id UUID NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    target_node_id UUID NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    
    edge_type edge_type NOT NULL,
    label TEXT,
    
    -- Discovery
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    discovery_method TEXT DEFAULT 'crawl',
    
    -- Edge properties
    weight FLOAT DEFAULT 1.0,
    is_bidirectional BOOLEAN DEFAULT FALSE,
    
    -- Data flow analysis
    data_transferred JSONB DEFAULT '{}',
    contains_sensitive_data BOOLEAN DEFAULT FALSE,
    
    -- Risk propagation
    propagation_factor FLOAT DEFAULT 0.5 CHECK (propagation_factor >= 0 AND propagation_factor <= 1),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    
    properties JSONB DEFAULT '{}',
    
    UNIQUE(session_id, source_node_id, target_node_id, edge_type)
);

-- =====================================================
-- 4. Node Vulnerabilities - Security findings per node
-- =====================================================
CREATE TABLE IF NOT EXISTS graph_node_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id UUID NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES graph_sessions(id) ON DELETE CASCADE,
    
    -- Vulnerability details
    vulnerability_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title TEXT NOT NULL,
    description TEXT,
    
    -- Classification
    owasp_category TEXT,
    cwe_id TEXT,
    cvss_score FLOAT,
    cvss_vector TEXT,
    
    -- Evidence
    evidence TEXT,
    request_sample TEXT,
    response_sample TEXT,
    parameter TEXT,
    payload TEXT,
    
    -- Remediation
    remediation TEXT,
    references JSONB DEFAULT '[]',
    
    -- Status
    status TEXT DEFAULT 'open' CHECK (status IN ('open', 'confirmed', 'false_positive', 'fixed', 'accepted')),
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    
    -- Source
    scan_source TEXT,
    scanner_name TEXT,
    confidence FLOAT DEFAULT 0.8,
    
    properties JSONB DEFAULT '{}'
);

-- =====================================================
-- 5. Graph Snapshots - For temporal analysis
-- =====================================================
CREATE TABLE IF NOT EXISTS graph_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES graph_sessions(id) ON DELETE CASCADE,
    
    snapshot_at TIMESTAMPTZ DEFAULT NOW(),
    snapshot_type TEXT DEFAULT 'auto' CHECK (snapshot_type IN ('auto', 'manual', 'milestone', 'scheduled')),
    label TEXT,
    
    -- Snapshot metrics
    total_nodes INTEGER DEFAULT 0,
    total_edges INTEGER DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    
    -- Risk metrics at snapshot time
    attack_surface_score FLOAT DEFAULT 0,
    avg_risk_score FLOAT DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    
    -- Cluster distribution
    clusters JSONB DEFAULT '{}',
    
    -- Serialized graph state
    nodes_snapshot JSONB,
    edges_snapshot JSONB,
    
    -- Diff from previous
    diff_summary JSONB DEFAULT '{
        "nodes_added": 0,
        "nodes_removed": 0,
        "edges_added": 0,
        "edges_removed": 0,
        "vulns_added": 0,
        "vulns_fixed": 0
    }',
    
    properties JSONB DEFAULT '{}'
);

-- =====================================================
-- 6. Attack Paths - Identified exploit chains
-- =====================================================
CREATE TABLE IF NOT EXISTS graph_attack_paths (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES graph_sessions(id) ON DELETE CASCADE,
    
    -- Path definition
    path_name TEXT,
    path_type TEXT DEFAULT 'automated' CHECK (path_type IN ('automated', 'manual', 'ai_suggested')),
    
    -- Path nodes (ordered)
    node_ids UUID[] NOT NULL,
    edge_ids UUID[] NOT NULL,
    
    -- Entry and target
    entry_node_id UUID REFERENCES graph_nodes(id),
    target_node_id UUID REFERENCES graph_nodes(id),
    
    -- Risk assessment
    total_risk_score FLOAT DEFAULT 0,
    exploitability_score FLOAT DEFAULT 0,
    impact_score FLOAT DEFAULT 0,
    path_length INTEGER DEFAULT 0,
    
    -- Vulnerabilities in path
    vulnerability_ids UUID[] DEFAULT '{}',
    vulnerability_chain TEXT,
    
    -- AI analysis
    ai_explanation TEXT,
    attack_narrative TEXT,
    
    -- Status
    is_verified BOOLEAN DEFAULT FALSE,
    is_exploitable BOOLEAN,
    
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    properties JSONB DEFAULT '{}'
);

-- =====================================================
-- 7. Graph Clusters - Functional zones
-- =====================================================
CREATE TABLE IF NOT EXISTS graph_clusters (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES graph_sessions(id) ON DELETE CASCADE,
    
    cluster_id TEXT NOT NULL,
    cluster_label TEXT NOT NULL,
    cluster_type TEXT,
    
    -- Cluster composition
    node_count INTEGER DEFAULT 0,
    node_ids UUID[] DEFAULT '{}',
    
    -- Metrics
    avg_risk_score FLOAT DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    
    -- Visual
    color TEXT,
    center_x FLOAT,
    center_y FLOAT,
    
    properties JSONB DEFAULT '{}',
    
    UNIQUE(session_id, cluster_id)
);

-- =====================================================
-- Indexes for performance
-- =====================================================

-- Sessions
CREATE INDEX IF NOT EXISTS idx_graph_sessions_target ON graph_sessions(target_domain);
CREATE INDEX IF NOT EXISTS idx_graph_sessions_status ON graph_sessions(status);
CREATE INDEX IF NOT EXISTS idx_graph_sessions_scan ON graph_sessions(scan_id);

-- Nodes
CREATE INDEX IF NOT EXISTS idx_graph_nodes_session ON graph_nodes(session_id);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_url_hash ON graph_nodes(url_hash);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_parent ON graph_nodes(parent_node_id);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_cluster ON graph_nodes(cluster_id);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_risk ON graph_nodes(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_depth ON graph_nodes(depth);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_active ON graph_nodes(is_active);

-- Edges
CREATE INDEX IF NOT EXISTS idx_graph_edges_session ON graph_edges(session_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target_node_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_type ON graph_edges(edge_type);

-- Vulnerabilities
CREATE INDEX IF NOT EXISTS idx_graph_vulns_node ON graph_node_vulnerabilities(node_id);
CREATE INDEX IF NOT EXISTS idx_graph_vulns_session ON graph_node_vulnerabilities(session_id);
CREATE INDEX IF NOT EXISTS idx_graph_vulns_severity ON graph_node_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_graph_vulns_status ON graph_node_vulnerabilities(status);

-- Snapshots
CREATE INDEX IF NOT EXISTS idx_graph_snapshots_session ON graph_snapshots(session_id);
CREATE INDEX IF NOT EXISTS idx_graph_snapshots_time ON graph_snapshots(snapshot_at DESC);

-- Attack paths
CREATE INDEX IF NOT EXISTS idx_graph_paths_session ON graph_attack_paths(session_id);
CREATE INDEX IF NOT EXISTS idx_graph_paths_risk ON graph_attack_paths(total_risk_score DESC);

-- Clusters
CREATE INDEX IF NOT EXISTS idx_graph_clusters_session ON graph_clusters(session_id);

-- =====================================================
-- Triggers for auto-updating
-- =====================================================

-- Update session stats when nodes change
CREATE OR REPLACE FUNCTION update_session_node_stats()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE graph_sessions SET
        stats = jsonb_set(
            jsonb_set(
                stats,
                '{total_nodes}',
                (SELECT COUNT(*)::text::jsonb FROM graph_nodes WHERE session_id = COALESCE(NEW.session_id, OLD.session_id) AND is_active = TRUE)
            ),
            '{max_depth_reached}',
            (SELECT COALESCE(MAX(depth), 0)::text::jsonb FROM graph_nodes WHERE session_id = COALESCE(NEW.session_id, OLD.session_id))
        ),
        updated_at = NOW()
    WHERE id = COALESCE(NEW.session_id, OLD.session_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_session_node_stats
AFTER INSERT OR UPDATE OR DELETE ON graph_nodes
FOR EACH ROW EXECUTE FUNCTION update_session_node_stats();

-- Update session stats when edges change
CREATE OR REPLACE FUNCTION update_session_edge_stats()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE graph_sessions SET
        stats = jsonb_set(
            stats,
            '{total_edges}',
            (SELECT COUNT(*)::text::jsonb FROM graph_edges WHERE session_id = COALESCE(NEW.session_id, OLD.session_id) AND is_active = TRUE)
        ),
        updated_at = NOW()
    WHERE id = COALESCE(NEW.session_id, OLD.session_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_session_edge_stats
AFTER INSERT OR UPDATE OR DELETE ON graph_edges
FOR EACH ROW EXECUTE FUNCTION update_session_edge_stats();

-- Update node vulnerability count
CREATE OR REPLACE FUNCTION update_node_vuln_count()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE graph_nodes SET
        vulnerability_count = (
            SELECT COUNT(*) FROM graph_node_vulnerabilities 
            WHERE node_id = COALESCE(NEW.node_id, OLD.node_id) AND status != 'fixed'
        ),
        risk_score = LEAST(100, (
            SELECT COALESCE(SUM(
                CASE severity
                    WHEN 'critical' THEN 40
                    WHEN 'high' THEN 25
                    WHEN 'medium' THEN 15
                    WHEN 'low' THEN 5
                    ELSE 1
                END
            ), 0)
            FROM graph_node_vulnerabilities 
            WHERE node_id = COALESCE(NEW.node_id, OLD.node_id) AND status != 'fixed'
        ))
    WHERE id = COALESCE(NEW.node_id, OLD.node_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_node_vuln_count
AFTER INSERT OR UPDATE OR DELETE ON graph_node_vulnerabilities
FOR EACH ROW EXECUTE FUNCTION update_node_vuln_count();

-- =====================================================
-- RLS Policies
-- =====================================================
ALTER TABLE graph_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE graph_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE graph_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE graph_node_vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE graph_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE graph_attack_paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE graph_clusters ENABLE ROW LEVEL SECURITY;

-- Allow all access (adjust for production)
CREATE POLICY "Enable all access for graph_sessions" ON graph_sessions FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Enable all access for graph_nodes" ON graph_nodes FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Enable all access for graph_edges" ON graph_edges FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Enable all access for graph_node_vulnerabilities" ON graph_node_vulnerabilities FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Enable all access for graph_snapshots" ON graph_snapshots FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Enable all access for graph_attack_paths" ON graph_attack_paths FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Enable all access for graph_clusters" ON graph_clusters FOR ALL USING (true) WITH CHECK (true);

-- =====================================================
-- Grants
-- =====================================================
GRANT ALL ON graph_sessions TO postgres, anon, authenticated, service_role;
GRANT ALL ON graph_nodes TO postgres, anon, authenticated, service_role;
GRANT ALL ON graph_edges TO postgres, anon, authenticated, service_role;
GRANT ALL ON graph_node_vulnerabilities TO postgres, anon, authenticated, service_role;
GRANT ALL ON graph_snapshots TO postgres, anon, authenticated, service_role;
GRANT ALL ON graph_attack_paths TO postgres, anon, authenticated, service_role;
GRANT ALL ON graph_clusters TO postgres, anon, authenticated, service_role;

-- =====================================================
-- Verification
-- =====================================================
DO $$
BEGIN
    RAISE NOTICE 'Graph Sitemap migration completed successfully!';
    RAISE NOTICE 'Tables created: graph_sessions, graph_nodes, graph_edges, graph_node_vulnerabilities, graph_snapshots, graph_attack_paths, graph_clusters';
END $$;
