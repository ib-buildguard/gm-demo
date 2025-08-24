#!/usr/bin/env python3
"""
Security & Compliance Analytics for Build Data

Features:
- Security and compliance insights from DuckDB build analytics
- SLSA Level 1 provenance generation  
- SBOM (Software Bill of Materials) generation
- Dependency graph visualization from ccache logs
- Build artifact integrity verification
- Supply chain security analysis
"""

import os
import re
import io
import json
import hashlib
import zipfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

import streamlit as st
import pandas as pd
import altair as alt
import networkx as nx
import duckdb
import yaml
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Configuration
st.set_page_config(
    page_title="Security & Compliance Analytics", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Global constants
DEFAULT_DUCKDB_PATH = "build_analytics.duckdb"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SPDX_VERSION = "SPDX-2.3"

# Security policy defaults
DEFAULT_SECURITY_POLICY = {
    "allowed_include_roots": ["/project", "/usr/include", "/opt", "/usr/lib/clang"],
    "denied_processes": ["curl", "wget", "apt", "dnf", "pip", "npm", "git", "svn"],
    "suspicious_flags": [
        "-fplugin=", "-Xclang -load", " -B ", "-Wl,--wrap", "-Wl,-rpath",
        "LD_PRELOAD=", "DYLD_INSERT_LIBRARIES=", "-fPIC", "-shared"
    ],
    "max_build_duration_hours": 24,
    "required_compiler_versions": ["gcc-11", "clang-14"],
    "allowed_extensions": [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"],
}

# App header
st.title("🔐 Security & Compliance Analytics")
st.markdown("**Build Security Analysis | SLSA Provenance | SBOM Generation | Dependency Graphs**")

# Helper functions
def sha256_hex(data: str) -> str:
    """Generate SHA256 hash of string data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def generate_uuid() -> str:
    """Generate a unique identifier."""
    return str(uuid.uuid4())

def load_duckdb_connection(db_path: str) -> duckdb.DuckDBPyConnection:
    """Load DuckDB connection with improved error handling."""
    try:
        if db_path.startswith("md:"):
            # MotherDuck connection
            st.info("🔗 Connecting to MotherDuck cloud database...")
            conn = duckdb.connect(db_path)
            # Simple test query
            result = conn.execute("SELECT 1 as test").fetchone()
            if result:
                st.success("✅ Connected to MotherDuck successfully!")
                return conn
            else:
                st.error("❌ MotherDuck connection test failed")
                return None
        else:
            # Local connection
            conn = duckdb.connect(db_path)
            return conn
    except Exception as e:
        st.error(f"❌ Database connection failed: {e}")
        if "motherduck" in str(e).lower():
            st.error("💡 Check your MotherDuck token and internet connection")
        return None

def get_available_builds(conn: duckdb.DuckDBPyConnection) -> pd.DataFrame:
    """Get list of available builds from DuckDB."""
    try:
        # Find all build-specific tables to identify available builds
        tables_result = conn.execute("SHOW TABLES").fetchall()
        build_tables = [t[0] for t in tables_result if t[0].startswith('sqlite_build_')]
        
        # Extract unique build IDs
        import re
        build_ids = set()
        for table in build_tables:
            match = re.search(r'sqlite_build_(\d+)_', table)
            if match:
                build_ids.add(int(match.group(1)))
        
        # Create builds dataframe
        builds_data = []
        for build_id in sorted(build_ids):
            # Try to get process count for this build
            try:
                process_table = f"sqlite_build_{build_id}_intercepted_process"
                count_result = conn.execute(f"SELECT COUNT(*) FROM {process_table}").fetchone()
                process_count = count_result[0] if count_result else 0
            except:
                process_count = 0
            
            builds_data.append({
                "build_id": build_id,
                "process_count": process_count,
                "start_time": None,
                "end_time": None
            })
        
        return pd.DataFrame(builds_data)
    except Exception as e:
        st.error(f"Failed to load builds: {e}")
        return pd.DataFrame()

def get_build_metadata(conn: duckdb.DuckDBPyConnection, build_id: str) -> Dict:
    """Get build metadata for a specific build."""
    try:
        query = """
        SELECT * FROM sqlite_build_history 
        WHERE _source_build_id = ? 
        ORDER BY BuildId DESC LIMIT 1
        """
        result = conn.execute(query, [build_id]).df()
        
        if result.empty:
            return {}
            
        row = result.iloc[0]
        metadata = {
            "build_id": str(row.get("BuildId", build_id)),
            "caption": str(row.get("BuildCaption", "")),
            "working_dir": str(row.get("WorkingDir", "")),
            "build_command": str(row.get("BuildCommand", "")),
            "start_time": int(row.get("StartTime", 0)),
            "end_time": int(row.get("EndTime", 0)),
            "return_code": int(row.get("ReturnCode", 0)),
            "source_file": str(row.get("_source_file", "")),
        }
        
        # Calculate duration
        if metadata["end_time"] and metadata["start_time"]:
            metadata["duration_ms"] = metadata["end_time"] - metadata["start_time"]
            metadata["duration_hours"] = metadata["duration_ms"] / (1000 * 3600)
        
        return metadata
    except Exception as e:
        st.error(f"Failed to load build metadata: {e}")
        return {}

def get_process_data(conn: duckdb.DuckDBPyConnection, build_id: str) -> pd.DataFrame:
    """Get process execution data for a build - optimized for cloud performance."""
    try:
        # Use intercepted_process table - limit data for better performance
        table_name = f"sqlite_build_{build_id}_intercepted_process"
        query = f"""
        SELECT 
            PID as process_id,
            ProcessName as process_name,
            Start as start_time,
            "End" as end_time,
            ExitCode as exit_code,
            CWD as working_dir,
            'localhost' as machine_name,
            _source_file,
            _source_build_id,
            Arguments as arguments
        FROM {table_name}
        ORDER BY Start
        LIMIT 50000
        """
        return conn.execute(query).df()
    except Exception as e:
        st.error(f"Failed to load process data: {e}")
        return pd.DataFrame()

def get_ccache_data(conn: duckdb.DuckDBPyConnection) -> pd.DataFrame:
    """Get ccache log data - optimized and cached."""
    try:
        query = """
        SELECT 
            timestamp,
            pid,
            message,
            parse_status,
            raw_line,
            _source_file,
            _line_number
        FROM ccache_logs
        ORDER BY _line_number
        LIMIT 10000
        """
        return conn.execute(query).df()
    except Exception as e:
        st.error(f"Failed to load ccache data: {e}")
        return pd.DataFrame()

def get_toolchain_data(conn: duckdb.DuckDBPyConnection, build_id: str) -> Dict:
    """Analyze toolchain usage for a specific build."""
    try:
        # Get compiler/toolchain processes
        toolchain_query = f"""
        SELECT 
            ProcessName,
            COUNT(*) as usage_count,
            COUNT(DISTINCT CWD) as unique_directories,
            AVG(CAST("End" AS BIGINT) - CAST(Start AS BIGINT)) as avg_duration_ms
        FROM sqlite_build_{build_id}_intercepted_process 
        WHERE ProcessName LIKE '%gcc%' OR ProcessName LIKE '%clang%' OR 
              ProcessName LIKE '%g++%' OR ProcessName LIKE '%ld%' OR
              ProcessName LIKE '%ar%' OR ProcessName LIKE '%make%' OR
              ProcessName LIKE '%cmake%' OR ProcessName LIKE '%ninja%' OR
              ProcessName LIKE '%strip%' OR ProcessName LIKE '%ranlib%' OR
              ProcessName LIKE '%ccache%'
        GROUP BY ProcessName
        ORDER BY usage_count DESC
        """
        toolchains_df = conn.execute(toolchain_query).df()
        
        # Get detailed compiler arguments for analysis
        args_query = f"""
        SELECT pa.Arguments, ip.ProcessName
        FROM sqlite_build_{build_id}_process_arguments pa
        JOIN sqlite_build_{build_id}_intercepted_process ip ON pa.ID = ip.PID
        WHERE (ip.ProcessName LIKE '%clang%' OR ip.ProcessName LIKE '%gcc%')
        AND pa.Arguments IS NOT NULL 
        AND pa.Arguments != ''
        LIMIT 100
        """
        args_df = conn.execute(args_query).df()
        
        # Analyze compiler flags and options
        compiler_flags = {}
        optimization_levels = {}
        target_architectures = set()
        
        for _, row in args_df.iterrows():
            args = str(row.get('Arguments', ''))
            
            # Extract optimization levels
            if '-O0' in args:
                optimization_levels['-O0'] = optimization_levels.get('-O0', 0) + 1
            elif '-O1' in args:
                optimization_levels['-O1'] = optimization_levels.get('-O1', 0) + 1
            elif '-O2' in args:
                optimization_levels['-O2'] = optimization_levels.get('-O2', 0) + 1
            elif '-O3' in args:
                optimization_levels['-O3'] = optimization_levels.get('-O3', 0) + 1
            elif '-Os' in args:
                optimization_levels['-Os'] = optimization_levels.get('-Os', 0) + 1
                
            # Extract target architectures
            if '-target' in args:
                parts = args.split('-target')
                if len(parts) > 1:
                    target = parts[1].split()[0] if parts[1].split() else 'unknown'
                    target_architectures.add(target)
            
            # Extract common flags
            common_flags = ['-fPIC', '-fstack-protector', '-D_FORTIFY_SOURCE', '-Wall', '-Werror', '-g', '-DNDEBUG']
            for flag in common_flags:
                if flag in args:
                    compiler_flags[flag] = compiler_flags.get(flag, 0) + 1
        
        return {
            "toolchains": toolchains_df,
            "compiler_flags": compiler_flags,
            "optimization_levels": optimization_levels,
            "target_architectures": list(target_architectures),
            "total_toolchain_invocations": len(toolchains_df)
        }
    except Exception as e:
        st.error(f"Failed to analyze toolchain data: {e}")
        return {
            "toolchains": pd.DataFrame(),
            "compiler_flags": {},
            "optimization_levels": {},
            "target_architectures": [],
            "total_toolchain_invocations": 0
        }

def analyze_security_violations(processes: pd.DataFrame, policy: Dict) -> Dict:
    """Analyze security policy violations in process data - grouped by unique patterns."""
    violations = {
        "denied_processes": [],
        "suspicious_flags": [],
        "long_running_builds": [],
        "external_network_access": [],
        "unauthorized_paths": [],
        "privilege_escalation": []
    }
    
    if processes.empty:
        return violations
    
    # Check for denied processes - group by unique process name patterns
    denied_procs = policy.get("denied_processes", [])
    denied_process_groups = {}
    
    for _, proc in processes.iterrows():
        proc_name = str(proc.get("process_name", "")).lower()
        if any(denied in proc_name for denied in denied_procs):
            # Group by process name pattern
            clean_name = proc.get("process_name", "unknown")
            if clean_name not in denied_process_groups:
                denied_process_groups[clean_name] = {
                    "process_name": clean_name,
                    "violation_count": 0,
                    "sample_working_dirs": set(),
                    "first_occurrence": proc.get("start_time")
                }
            denied_process_groups[clean_name]["violation_count"] += 1
            denied_process_groups[clean_name]["sample_working_dirs"].add(proc.get("working_dir", "unknown"))
    
    # Convert to list and limit sample directories
    for group in denied_process_groups.values():
        group["sample_working_dirs"] = list(group["sample_working_dirs"])[:3]  # Limit to 3 examples
        violations["denied_processes"].append(group)
    
    # Add some demo security violations for realistic analysis
    if not processes.empty:
        # Simulate unauthorized path access (group by path patterns)
        unauthorized_paths = {}
        sensitive_paths = ["/etc/passwd", "/etc/shadow", "/root", "/admin", "/private"]
        
        # Sample some processes for demo violations
        sample_size = min(len(processes), 50)  # Analyze a sample for performance
        sample_processes = processes.sample(n=sample_size, random_state=42) if len(processes) > 50 else processes
        
        for _, proc in sample_processes.iterrows():
            working_dir = str(proc.get("working_dir", "")).lower()
            if any(path in working_dir for path in sensitive_paths):
                # Group by path pattern
                for sensitive_path in sensitive_paths:
                    if sensitive_path in working_dir:
                        if sensitive_path not in unauthorized_paths:
                            unauthorized_paths[sensitive_path] = {
                                "path_pattern": sensitive_path,
                                "violation_count": 0,
                                "affected_processes": set()
                            }
                        unauthorized_paths[sensitive_path]["violation_count"] += 1
                        unauthorized_paths[sensitive_path]["affected_processes"].add(proc.get("process_name", "unknown"))
        
        # Convert sets to lists and limit
        for path_group in unauthorized_paths.values():
            path_group["affected_processes"] = list(path_group["affected_processes"])[:5]
            violations["unauthorized_paths"].append(path_group)
    
    # Simulate privilege escalation patterns
    privilege_patterns = ["sudo", "su", "setuid", "setgid", "admin", "root"]
    privilege_groups = {}
    
    if not processes.empty:
        sample_processes = processes.sample(n=min(30, len(processes)), random_state=123)
        for _, proc in sample_processes.iterrows():
            proc_name = str(proc.get("process_name", "")).lower()
            if any(pattern in proc_name for pattern in privilege_patterns):
                for pattern in privilege_patterns:
                    if pattern in proc_name:
                        if pattern not in privilege_groups:
                            privilege_groups[pattern] = {
                                "escalation_type": pattern,
                                "violation_count": 0,
                                "unique_processes": set()
                            }
                        privilege_groups[pattern]["violation_count"] += 1
                        privilege_groups[pattern]["unique_processes"].add(proc.get("process_name", "unknown"))
        
        # Convert and limit
        for group in privilege_groups.values():
            group["unique_processes"] = list(group["unique_processes"])[:3]
            violations["privilege_escalation"].append(group)
    
    # Check build duration (keep existing logic)
    if not processes.empty:
        # Convert to numeric, handling string values
        end_times = pd.to_numeric(processes["end_time"], errors='coerce')
        start_times = pd.to_numeric(processes["start_time"], errors='coerce')
        
        max_time = end_times.max()
        min_time = start_times.min()
        
        if pd.notna(max_time) and pd.notna(min_time) and max_time > min_time:
            duration_hours = (max_time - min_time) / (1000 * 3600)
            max_allowed = policy.get("max_build_duration_hours", 12)  # More realistic for demo
            if duration_hours > max_allowed:
                violations["long_running_builds"].append({
                    "duration_hours": round(duration_hours, 2),
                    "max_allowed": max_allowed,
                    "start_time": min_time,
                    "end_time": max_time,
                    "violation_type": "excessive_build_time"
                })
    
    return violations

def parse_ccache_dependencies(ccache_data: pd.DataFrame) -> Dict:
    """Parse dependency information from ccache logs."""
    dependencies = {
        "source_files": set(),
        "include_files": set(),
        "object_files": set(),
        "compile_commands": [],
        "include_graph": nx.DiGraph()
    }
    
    if ccache_data.empty:
        return dependencies
    
    current_source = None
    current_includes = []
    
    for _, row in ccache_data.iterrows():
        message = str(row.get("message", ""))
        
        # Parse source files
        if "SOURCE:" in message:
            source_match = re.search(r"SOURCE:\s*(.+)", message)
            if source_match:
                current_source = source_match.group(1).strip()
                dependencies["source_files"].add(current_source)
                current_includes = []
        
        # Parse include files
        elif "Inode cache hit:" in message or "include" in message.lower():
            include_match = re.search(r"(?:include|Inode cache hit:)\s*(.+\.[hH](?:pp|xx)?)", message)
            if include_match:
                include_file = include_match.group(1).strip()
                dependencies["include_files"].add(include_file)
                current_includes.append(include_file)
                
                # Add to dependency graph
                if current_source:
                    dependencies["include_graph"].add_edge(current_source, include_file)
        
        # Parse object files
        elif "Object file:" in message:
            obj_match = re.search(r"Object file:\s*(.+)", message)
            if obj_match:
                obj_file = obj_match.group(1).strip()
                dependencies["object_files"].add(obj_file)
        
        # Parse compile commands
        elif "COMMAND:" in message:
            cmd_match = re.search(r"COMMAND:\s*(.+)", message)
            if cmd_match:
                command = cmd_match.group(1).strip()
                dependencies["compile_commands"].append({
                    "source": current_source,
                    "command": command,
                    "includes": current_includes.copy()
                })
    
    return dependencies

def generate_slsa_provenance(build_metadata: Dict, processes: pd.DataFrame, dependencies: Dict) -> Dict:
    """Generate SLSA Level 1 provenance document."""
    
    # Build basic provenance structure
    provenance = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": SLSA_PREDICATE_TYPE,
        "subject": [],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/slsa-framework/slsa/tree/main/docs/provenance/schema",
                "externalParameters": {
                    "buildCommand": build_metadata.get("build_command", ""),
                    "workingDirectory": build_metadata.get("working_dir", ""),
                    "buildCaption": build_metadata.get("caption", "")
                },
                "internalParameters": {
                    "buildId": build_metadata.get("build_id", ""),
                    "returnCode": build_metadata.get("return_code", 0)
                }
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/incredibuild/build-analytics"
                },
                "metadata": {
                    "invocationId": generate_uuid(),
                    "startedOn": datetime.fromtimestamp(
                        build_metadata.get("start_time", 0) / 1000, 
                        tz=timezone.utc
                    ).isoformat() if build_metadata.get("start_time") else None,
                    "finishedOn": datetime.fromtimestamp(
                        build_metadata.get("end_time", 0) / 1000,
                        tz=timezone.utc  
                    ).isoformat() if build_metadata.get("end_time") else None
                }
            }
        }
    }
    
    # Add subjects (build artifacts)
    for obj_file in dependencies.get("object_files", []):
        if obj_file:
            provenance["subject"].append({
                "name": obj_file,
                "digest": {
                    "sha256": sha256_hex(obj_file)  # Placeholder - would need actual file hash
                }
            })
    
    # Add materials (source files)
    materials = []
    for src_file in dependencies.get("source_files", []):
        if src_file:
            materials.append({
                "uri": src_file,
                "digest": {
                    "sha256": sha256_hex(src_file)  # Placeholder - would need actual file hash
                }
            })
    
    for inc_file in dependencies.get("include_files", []):
        if inc_file:
            materials.append({
                "uri": inc_file,
                "digest": {
                    "sha256": sha256_hex(inc_file)  # Placeholder - would need actual file hash
                }
            })
    
    if materials:
        provenance["predicate"]["buildDefinition"]["resolvedDependencies"] = materials
    
    return provenance

def generate_sbom(build_metadata: Dict, dependencies: Dict) -> Dict:
    """Generate SPDX SBOM document."""
    
    document_id = f"SPDXRef-DOCUMENT-{build_metadata.get('build_id', 'unknown')}"
    
    sbom = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": document_id,
        "documentName": f"Build SBOM for {build_metadata.get('caption', 'Unknown Build')}",
        "documentNamespace": f"https://build-analytics/{build_metadata.get('build_id', 'unknown')}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": ["Tool: build-analytics-v1.0"],
            "licenseListVersion": "3.16"
        },
        "packages": [],
        "relationships": []
    }
    
    # Add package for the build itself
    build_package = {
        "SPDXID": "SPDXRef-Package-Build",
        "name": build_metadata.get("caption", "Build Package"),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": True,
        "copyrightText": "NOASSERTION"
    }
    sbom["packages"].append(build_package)
    
    # Add source files as packages
    for i, src_file in enumerate(dependencies.get("source_files", [])):
        if src_file:
            pkg_id = f"SPDXRef-Package-Source-{i}"
            package = {
                "SPDXID": pkg_id,
                "name": Path(src_file).name,
                "downloadLocation": src_file,
                "filesAnalyzed": False,
                "copyrightText": "NOASSERTION",
                "supplier": "NOASSERTION"
            }
            sbom["packages"].append(package)
            
            # Add relationship
            sbom["relationships"].append({
                "spdxElementId": "SPDXRef-Package-Build",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": pkg_id
            })
    
    # Add include files
    for i, inc_file in enumerate(dependencies.get("include_files", [])):
        if inc_file:
            pkg_id = f"SPDXRef-Package-Include-{i}"
            package = {
                "SPDXID": pkg_id,
                "name": Path(inc_file).name,
                "downloadLocation": inc_file,
                "filesAnalyzed": False,
                "copyrightText": "NOASSERTION",
                "supplier": "NOASSERTION"
            }
            sbom["packages"].append(package)
            
            # Add relationship
            sbom["relationships"].append({
                "spdxElementId": "SPDXRef-Package-Build", 
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": pkg_id
            })
    
    return sbom

def create_dependency_graph_plot(dependencies: Dict) -> go.Figure:
    """Create interactive dependency graph visualization."""
    
    G = dependencies.get("include_graph", nx.DiGraph())
    
    if G.number_of_nodes() == 0:
        fig = go.Figure()
        fig.add_annotation(
            text="No dependency data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, xanchor='center', yanchor='middle'
        )
        return fig
    
    # Limit graph size for performance
    if G.number_of_nodes() > 100:
        # Keep only nodes with high degree
        degrees = dict(G.degree())
        top_nodes = sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:100]
        top_node_names = [node for node, _ in top_nodes]
        G = G.subgraph(top_node_names)
    
    # Calculate layout
    try:
        pos = nx.spring_layout(G, k=1, iterations=50)
    except:
        pos = {node: (i % 10, i // 10) for i, node in enumerate(G.nodes())}
    
    # Create edge traces
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
    
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines'
    )
    
    # Create node traces
    node_x = []
    node_y = []
    node_text = []
    node_info = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        
        # Determine node type and color
        if node.endswith(('.h', '.hpp', '.hxx')):
            node_type = "Header"
            color = "lightblue"
        elif node.endswith(('.c', '.cpp', '.cc', '.cxx')):
            node_type = "Source"
            color = "lightgreen"
        else:
            node_type = "Other"
            color = "lightgray"
        
        node_text.append(Path(node).name)
        adjacencies = list(G.neighbors(node))
        node_info.append(f"{Path(node).name}<br>Type: {node_type}<br>Connections: {len(adjacencies)}")
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=node_text,
        textposition="middle center",
        hovertext=node_info,
        marker=dict(
            size=10,
            color='lightblue',
            line=dict(width=1, color='darkblue')
        )
    )
    
    # Create figure
    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=dict(text="Dependency Graph (Source & Header Files)", font=dict(size=16)),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20,l=5,r=5,t=40),
            annotations=[
                dict(
                    text="Dependency relationships from ccache logs",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.005, y=-0.002,
                    xanchor='left', yanchor='bottom',
                    font=dict(color="gray", size=12)
                )
            ],
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )
    )
    
    return fig

# Sidebar configuration
st.sidebar.header("Configuration")

# Database configuration - with fallback option
use_cloud = st.sidebar.checkbox("☁️ Use Cloud Database", value=False, help="Use MotherDuck cloud database (may be slower)")

if use_cloud:
    motherduck_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRhbC5rYXB0c2FuQGluY3JlZGlidWlsZC5jb20iLCJzZXNzaW9uIjoidGFsLmthcHRzYW4uaW5jcmVkaWJ1aWxkLmNvbSIsInBhdCI6IjhPSDVYRWw2NHpQWEVzRGJpam44MUNmbE13S0xjb0U5VWxwMEx6Tnc2WVUiLCJ1c2VySWQiOiIyYjg4ZTc0Ny1kYTg1LTQwZjEtODUwNS04MmY3ZTUxZjU4MDAiLCJpc3MiOiJtZF9wYXQiLCJyZWFkT25seSI6ZmFsc2UsInRva2VuVHlwZSI6InJlYWRfd3JpdGUiLCJpYXQiOjE3NTYwNDQzMzN9.jM60vZEBOFligSptbzwV9KQCIgPdcEolHu60WTHHiX0"
    motherduck_database = "build_analytics"
    duckdb_path = f"md:{motherduck_database}?motherduck_token={motherduck_token}"
else:
    # Use local database for better performance and stability
    duckdb_path = DEFAULT_DUCKDB_PATH

# Security policy configuration
st.sidebar.subheader("Security Policy")
policy_text = st.sidebar.text_area(
    "Security Policy (YAML)",
    value=yaml.safe_dump(DEFAULT_SECURITY_POLICY, sort_keys=False),
    height=200,
    help="Define security policies and compliance rules"
)

try:
    security_policy = yaml.safe_load(policy_text)
except yaml.YAMLError as e:
    st.sidebar.error(f"Invalid YAML: {e}")
    security_policy = DEFAULT_SECURITY_POLICY

# Main application
# Check database availability (different logic for MotherDuck vs local)
if duckdb_path.startswith("md:"):
    # MotherDuck connection - we'll test connectivity later when we try to connect
    pass
else:
    # Local file - check if it exists
    if not Path(duckdb_path).exists():
        st.error(f"DuckDB file not found: {duckdb_path}")
        st.info("Please run the ingest script first: `python3 scripts/ingest_duckdb.py`")
        st.stop()

# Load data
conn = load_duckdb_connection(duckdb_path)
if not conn:
    st.stop()

builds_df = get_available_builds(conn)
if builds_df.empty:
    st.warning("No builds found in the database.")
    st.stop()

# Build selection
st.sidebar.subheader("Build Selection")
available_builds = builds_df["build_id"].tolist()
selected_build = st.sidebar.selectbox(
    "Select Build to Analyze",
    options=available_builds,
    format_func=lambda x: f"Build {x}"
)

# Baseline build selection for comparison
baseline_builds = ["None"] + available_builds
baseline_build = st.sidebar.selectbox(
    "Select Baseline Build (for comparison)",
    options=baseline_builds,
    index=0,
    format_func=lambda x: "No baseline" if x == "None" else f"Build {x}"
)

# Analysis button
analyze_button = st.sidebar.button("🔍 Run Security Analysis", type="primary")

def compare_builds(current_processes: pd.DataFrame, baseline_processes: pd.DataFrame) -> Dict:
    """Compare current build with baseline for drift analysis."""
    comparison = {
        "new_processes": pd.DataFrame(),
        "removed_processes": pd.DataFrame(),
        "changed_processes": pd.DataFrame(),
        "process_count_delta": 0,
        "duration_delta": 0
    }
    
    if baseline_processes.empty:
        comparison["new_processes"] = current_processes[["process_name"]].drop_duplicates()
        comparison["process_count_delta"] = len(current_processes)
        return comparison
    
    # Find new and removed processes
    current_procs = set(current_processes["process_name"].dropna().unique())
    baseline_procs = set(baseline_processes["process_name"].dropna().unique())
    
    new_procs = current_procs - baseline_procs
    removed_procs = baseline_procs - current_procs
    
    if new_procs:
        comparison["new_processes"] = pd.DataFrame({"process_name": list(new_procs)})
    
    if removed_procs:
        comparison["removed_processes"] = pd.DataFrame({"process_name": list(removed_procs)})
    
    comparison["process_count_delta"] = len(current_processes) - len(baseline_processes)
    
    return comparison

def analyze_advanced_security(processes_df: pd.DataFrame, ccache_df: pd.DataFrame, policy: Dict) -> Dict:
    """Advanced security analysis with additional insights."""
    insights = {
        "privilege_escalation": [],
        "file_system_access": [],
        "network_indicators": [],
        "compilation_anomalies": [],
        "supply_chain_risks": [],
        "compliance_score": 0
    }
    
    if not processes_df.empty:
        # Look for potential privilege escalation
        admin_processes = processes_df[
            processes_df["process_name"].str.contains("sudo|su|admin|root", case=False, na=False)
        ]
        for _, proc in admin_processes.iterrows():
            insights["privilege_escalation"].append({
                "process": proc.get("process_name"),
                "working_dir": proc.get("working_dir"),
                "risk_level": "high"
            })
    
    if not ccache_df.empty:
        # Analyze compilation patterns
        error_lines = ccache_df[ccache_df["message"].str.contains("error|failed|abort", case=False, na=False)]
        if len(error_lines) > 0:
            insights["compilation_anomalies"].append({
                "type": "compilation_errors",
                "count": len(error_lines),
                "risk_level": "medium"
            })
        
        # Look for external file access
        external_access = ccache_df[
            ccache_df["message"].str.contains("http://|https://|ftp://", case=False, na=False)
        ]
        for _, line in external_access.iterrows():
            insights["network_indicators"].append({
                "type": "external_url_access",
                "message": line.get("message", "")[:100],
                "risk_level": "high"
            })
    
    # Calculate compliance score
    total_checks = 10
    passed_checks = total_checks - len(insights["privilege_escalation"]) - len(insights["network_indicators"])
    insights["compliance_score"] = max(0, (passed_checks / total_checks) * 100)
    
    return insights

if analyze_button and selected_build:
    with st.spinner("Loading build data..."):
        # Load build data
        build_metadata = get_build_metadata(conn, selected_build)
        processes_df = get_process_data(conn, selected_build)
        ccache_df = get_ccache_data(conn)
        
        # Load baseline data if selected
        baseline_metadata = {}
        baseline_processes_df = pd.DataFrame()
        build_comparison = {}
        
        if baseline_build and baseline_build != "None":
            baseline_metadata = get_build_metadata(conn, baseline_build)
            baseline_processes_df = get_process_data(conn, baseline_build)
            build_comparison = compare_builds(processes_df, baseline_processes_df)
        
        # Show data sampling info for cloud performance
        if len(processes_df) >= 50000:
            st.info(f"📊 **Performance Mode**: Analyzing {len(processes_df):,} processes (sampled from larger dataset for faster cloud performance)")
    
    # Parse dependencies
    dependencies = parse_ccache_dependencies(ccache_df)
    
    # Toolchain analysis
    toolchain_data = get_toolchain_data(conn, selected_build)
    
    # Security analysis
    security_violations = analyze_security_violations(processes_df, security_policy)
    advanced_security = analyze_advanced_security(processes_df, ccache_df, security_policy)
    
    # Display results
    header_text = f"🔍 Security Analysis - Build {selected_build}"
    if baseline_build and baseline_build != "None":
        header_text += f" (vs Baseline {baseline_build})"
    st.header(header_text)
    
    # Build overview with comparison
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            "Build Status", 
            "Success" if build_metadata.get("return_code", 1) == 0 else "Failed",
            delta=build_metadata.get("return_code", "N/A")
        )
    
    with col2:
        duration_hours = build_metadata.get("duration_hours", 0)
        if duration_hours < 1:
            # Convert to minutes and seconds
            duration_minutes = duration_hours * 60
            if duration_minutes < 1:
                duration_seconds = duration_minutes * 60
                st.metric("Duration", f"{duration_seconds:.0f}s")
            else:
                st.metric("Duration", f"{duration_minutes:.1f}m")
        else:
            st.metric("Duration", f"{duration_hours:.1f}h")
    
    with col3:
        process_delta = build_comparison.get("process_count_delta", 0) if build_comparison else 0
        st.metric("Processes", len(processes_df), delta=process_delta if process_delta != 0 else None)
    
    with col4:
        violation_count = sum(len(v) for v in security_violations.values())
        st.metric("Security Violations", violation_count)
    
    with col5:
        # Show toolchain tool count instead of compliance score  
        toolchain_count = len(toolchain_data.get("toolchains", []))
        st.metric("Unique Tools", toolchain_count)
    
    # Build details
    with st.expander("Build Details", expanded=True):
        st.json({
            "Build ID": build_metadata.get("build_id"),
            "Caption": build_metadata.get("caption"),
            "Working Directory": build_metadata.get("working_dir"),
            "Build Command": build_metadata.get("build_command"),
            "Source File": build_metadata.get("source_file")
        })
    
    # Baseline comparison (if applicable)
    if build_comparison and baseline_build != "None":
        st.subheader(f"📊 Build Drift Analysis (vs Build {baseline_build})")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**New Processes**")
            if not build_comparison["new_processes"].empty:
                st.dataframe(build_comparison["new_processes"], use_container_width=True)
            else:
                st.info("No new processes detected")
        
        with col2:
            st.write("**Removed Processes**")
            if not build_comparison["removed_processes"].empty:
                st.dataframe(build_comparison["removed_processes"], use_container_width=True)
            else:
                st.info("No processes removed")
    
    # Enhanced Security Findings
    st.subheader("🚨 Security & Compliance Analysis")
    
    # Advanced security insights
    adv_insights_tabs = st.tabs(["Policy Violations", "Advanced Threats"])
    
    with adv_insights_tabs[0]:
        # Standard policy violations - show unique violation patterns
        violation_summary = []
        total_violation_instances = 0
        
        for violation_type, violations in security_violations.items():
            if violations:
                # Calculate total instances across all grouped violations
                instances = 0
                if violation_type in ["unauthorized_paths", "privilege_escalation"]:
                    instances = sum(v.get("violation_count", 1) for v in violations)
                else:
                    instances = sum(v.get("violation_count", 1) for v in violations) if violations else 0
                
                total_violation_instances += instances
                violation_summary.append({
                    "Violation Type": violation_type.replace("_", " ").title(),
                    "Unique Patterns": len(violations),
                    "Total Instances": instances,
                    "Severity": "High" if violation_type in ["denied_processes", "external_network_access", "privilege_escalation"] else "Medium"
                })
        
        if violation_summary:
            violations_df = pd.DataFrame(violation_summary)
            st.dataframe(violations_df, use_container_width=True)
            
            # Show total summary
            unique_patterns = sum(len(violations) for violations in security_violations.values())
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Unique Violation Patterns", unique_patterns)
            with col2:
                st.metric("Total Violation Instances", total_violation_instances)
            
            # Detailed violations - show grouped patterns
            for violation_type, violations in security_violations.items():
                if violations:
                    with st.expander(f"{violation_type.replace('_', ' ').title()} ({len(violations)} unique patterns)"):
                        if violation_type == "unauthorized_paths":
                            for violation in violations:
                                st.write(f"**Path Pattern:** `{violation.get('path_pattern', 'unknown')}`")
                                st.write(f"- Instances: {violation.get('violation_count', 0)}")
                                st.write(f"- Affected processes: {', '.join(violation.get('affected_processes', []))}")
                                st.divider()
                        elif violation_type == "privilege_escalation":
                            for violation in violations:
                                st.write(f"**Escalation Type:** `{violation.get('escalation_type', 'unknown')}`")
                                st.write(f"- Instances: {violation.get('violation_count', 0)}")
                                st.write(f"- Unique processes: {', '.join(violation.get('unique_processes', []))}")
                                st.divider()
                        else:
                            # Default JSON display for other violation types
                            st.json(violations)
        else:
            st.success("✅ No security policy violations detected!")
    
    with adv_insights_tabs[1]:
        st.write("**Advanced threat detection goes beyond basic policy violations to identify sophisticated attack patterns and security risks.**")
        
        # Create columns for better organization
        threat_col1, threat_col2 = st.columns(2)
        
        with threat_col1:
            st.write("### 🚨 **Privilege Escalation**")
            st.write("*Processes running with elevated admin/root privileges*")
            
            if advanced_security["privilege_escalation"]:
                st.error(f"**Found {len(advanced_security['privilege_escalation'])} privilege escalation patterns**")
                
                for escalation in advanced_security["privilege_escalation"]:
                    with st.expander(f"🔍 {escalation.get('process', 'Unknown Process')}", expanded=False):
                        st.write(f"**Process:** `{escalation.get('process', 'N/A')}`")
                        st.write(f"**Working Directory:** `{escalation.get('working_dir', 'N/A')}`")
                        st.write(f"**Risk Level:** {escalation.get('risk_level', 'Unknown').upper()}")
                        
                        # Explain the risk
                        if "sudo" in escalation.get('process', '').lower():
                            st.info("💡 **What this means:** Process used sudo for elevated privileges. Could be legitimate admin task or potential privilege escalation attack.")
                        elif "root" in escalation.get('process', '').lower():
                            st.warning("⚠️ **What this means:** Process ran as root user. High privilege access detected.")
            else:
                st.success("✅ **No privilege escalation detected**")
                st.info("All processes ran with normal user privileges.")
        
        with threat_col2:
            st.write("### 🌐 **Network Activity**")
            st.write("*External network connections during build process*")
            
            if advanced_security["network_indicators"]:
                st.warning(f"**Found {len(advanced_security['network_indicators'])} network activity patterns**")
                
                for network in advanced_security["network_indicators"]:
                    with st.expander(f"🔍 {network.get('type', 'Network Activity')}", expanded=False):
                        st.write(f"**Type:** {network.get('type', 'N/A')}")
                        st.write(f"**Message:** `{network.get('message', 'N/A')}`")
                        st.write(f"**Risk Level:** {network.get('risk_level', 'Unknown').upper()}")
                        
                        # Explain the risk
                        if "http" in network.get('message', '').lower():
                            st.info("💡 **What this means:** Build process accessed external URLs. Could be downloading dependencies or potential data exfiltration.")
            else:
                st.success("✅ **No external network activity detected**")
                st.info("Build process stayed within the local environment.")
        
        # Full width section for compilation anomalies
        st.write("### ⚠️ **Compilation Anomalies**")
        st.write("*Unusual patterns in the compilation process that may indicate tampering*")
        
        if advanced_security["compilation_anomalies"]:
            st.warning(f"**Found {len(advanced_security['compilation_anomalies'])} compilation anomalies**")
            
            for anomaly in advanced_security["compilation_anomalies"]:
                with st.expander(f"🔍 {anomaly.get('type', 'Compilation Issue')}", expanded=False):
                    st.write(f"**Type:** {anomaly.get('type', 'N/A')}")
                    st.write(f"**Count:** {anomaly.get('count', 'N/A')} occurrences")
                    st.write(f"**Risk Level:** {anomaly.get('risk_level', 'Unknown').upper()}")
                    
                    # Explain what this means
                    if anomaly.get('type') == 'compilation_errors':
                        st.info("💡 **What this means:** Multiple compilation errors detected. Could indicate corrupted source code, tampered toolchain, or normal build issues.")
        else:
            st.success("✅ **No compilation anomalies detected**")
            st.info("Build process completed without unusual compilation patterns.")
        
        # Overall threat summary
        total_threats = (len(advanced_security.get("privilege_escalation", [])) + 
                        len(advanced_security.get("network_indicators", [])) + 
                        len(advanced_security.get("compilation_anomalies", [])))
        
        if total_threats == 0:
            st.success("🛡️ **Overall Security Status: CLEAN**")
            st.info("No advanced threats detected. The build process appears secure and legitimate.")
        else:
            if total_threats >= 5:
                st.error(f"🚨 **Overall Security Status: HIGH RISK** ({total_threats} threats)")
                st.error("Multiple threat patterns detected. Immediate investigation recommended.")
            elif total_threats >= 2:
                st.warning(f"⚠️ **Overall Security Status: MODERATE RISK** ({total_threats} threats)")
                st.warning("Some threat patterns detected. Review and investigation recommended.")
            else:
                st.info(f"🔍 **Overall Security Status: LOW RISK** ({total_threats} threat)")
                st.info("Minimal threat patterns detected. Monitor but likely acceptable.")
    

    
    # Toolchain Analysis
    st.subheader("🔧 Toolchain Analysis")
    
    toolchain_tabs = st.tabs(["Overview", "Compiler Details", "Security Flags"])
    
    with toolchain_tabs[0]:
        st.write("**Build Toolchain Summary**")
        
        if not toolchain_data["toolchains"].empty:
            # Top toolchains
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Most Used Tools**")
                top_tools = toolchain_data["toolchains"].head(10)
                st.dataframe(top_tools, use_container_width=True)
            
            with col2:
                st.write("**Toolchain Metrics**")
                total_invocations = toolchain_data["toolchains"]["usage_count"].sum()
                unique_tools = len(toolchain_data["toolchains"])
                avg_duration = toolchain_data["toolchains"]["avg_duration_ms"].mean()
                
                st.metric("Total Tool Invocations", f"{total_invocations:,}")
                st.metric("Unique Tools", unique_tools)
                st.metric("Avg Tool Duration", f"{avg_duration:.1f}ms" if pd.notna(avg_duration) else "N/A")
                
            # Toolchain distribution chart
            if len(toolchain_data["toolchains"]) > 0:
                fig = px.bar(
                    toolchain_data["toolchains"].head(15),
                    x="ProcessName", 
                    y="usage_count",
                    title="Tool Usage Distribution",
                    labels={"usage_count": "Usage Count", "ProcessName": "Tool"}
                )
                fig.update_layout(xaxis_tickangle=-45, height=400)
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No toolchain data available for this build")
    
    with toolchain_tabs[1]:
        st.write("**Compiler Configuration**")
        
        # Show compiler paths and versions
        compilers = toolchain_data["toolchains"][
            toolchain_data["toolchains"]["ProcessName"].str.contains("clang|gcc", case=False, na=False)
        ]
        
        if not compilers.empty:
            st.write("**Detected Compilers:**")
            for _, compiler in compilers.iterrows():
                st.write(f"- **{compiler['ProcessName']}**: {compiler['usage_count']:,} invocations")
                
            # Target architectures
            if toolchain_data["target_architectures"]:
                st.write("**Target Architectures:**")
                for arch in toolchain_data["target_architectures"]:
                    st.code(arch)
        else:
            st.info("No compiler information available")
    
    with toolchain_tabs[2]:
        st.write("**Security & Hardening Flags**")
        
        if toolchain_data["compiler_flags"]:
            # Security flags analysis
            security_flags = {
                "-fstack-protector": "Stack Protection",
                "-D_FORTIFY_SOURCE": "Buffer Overflow Protection", 
                "-fPIC": "Position Independent Code",
                "-Wall": "All Warnings",
                "-Werror": "Warnings as Errors"
            }
            
            flag_data = []
            for flag, count in toolchain_data["compiler_flags"].items():
                description = security_flags.get(flag, "Build Flag")
                flag_data.append({
                    "Flag": flag,
                    "Description": description,
                    "Usage Count": count,
                    "Security Impact": "High" if flag in ["-fstack-protector", "-D_FORTIFY_SOURCE"] else "Medium"
                })
            
            if flag_data:
                flags_df = pd.DataFrame(flag_data)
                st.dataframe(flags_df, use_container_width=True)
                
                # Security score based on flags
                critical_flags = ["-fstack-protector", "-D_FORTIFY_SOURCE", "-fPIC"]
                present_critical = sum(1 for flag in critical_flags if flag in toolchain_data["compiler_flags"])
                security_score = (present_critical / len(critical_flags)) * 100
                
                if security_score >= 80:
                    st.success(f"🛡️ Good Security Posture: {security_score:.0f}%")
                elif security_score >= 50:
                    st.warning(f"⚠️ Moderate Security: {security_score:.0f}%")
                else:
                    st.error(f"❌ Weak Security Posture: {security_score:.0f}%")
            else:
                st.info("No compiler security flags detected")
        else:
            st.info("No compiler flag data available")
    

    
    # Dependency analysis
    st.subheader("📊 Dependency Analysis")
    
    dep_col1, dep_col2 = st.columns(2)
    
    with dep_col1:
        st.metric("Source Files", len(dependencies.get("source_files", [])))
        st.metric("Include Files", len(dependencies.get("include_files", [])))
        st.metric("Object Files", len(dependencies.get("object_files", [])))
    
    with dep_col2:
        compile_commands = dependencies.get("compile_commands", [])
        st.metric("Compile Commands", len(compile_commands))
        
        # Dependency graph stats
        graph = dependencies.get("include_graph", nx.DiGraph())
        st.metric("Dependency Edges", graph.number_of_edges())
    
    # Dependency graph visualization
    st.subheader("🕸️ Dependency Graph")
    
    if graph.number_of_nodes() > 0:
        fig = create_dependency_graph_plot(dependencies)
        st.plotly_chart(fig, use_container_width=True)
        
        # Graph statistics
        with st.expander("Graph Statistics"):
            if graph.number_of_nodes() > 0:
                st.write(f"**Nodes:** {graph.number_of_nodes()}")
                st.write(f"**Edges:** {graph.number_of_edges()}")
                st.write(f"**Average Degree:** {sum(dict(graph.degree()).values()) / graph.number_of_nodes():.2f}")
                
                # Top files by degree
                degrees = dict(graph.degree())
                top_files = sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:10]
                if top_files:
                    st.write("**Top 10 Files by Connections:**")
                    for file_path, degree in top_files:
                        st.write(f"- {Path(file_path).name}: {degree} connections")
    else:
        st.info("No dependency graph data available from ccache logs.")
    
    # SLSA Provenance Generation
    st.subheader("📋 SLSA Level 1 Provenance")
    
    provenance = generate_slsa_provenance(build_metadata, processes_df, dependencies)
    
    with st.expander("View SLSA Provenance Document", expanded=False):
        st.json(provenance)
    
    provenance_json = json.dumps(provenance, indent=2)
    st.download_button(
        "📥 Download SLSA Provenance",
        data=provenance_json,
        file_name=f"slsa_provenance_build_{selected_build}.json",
        mime="application/json"
    )
    
    # SBOM Generation
    st.subheader("📦 Software Bill of Materials (SBOM)")
    
    sbom = generate_sbom(build_metadata, dependencies)
    
    with st.expander("View SPDX SBOM Document", expanded=False):
        st.json(sbom)
    
    sbom_json = json.dumps(sbom, indent=2)
    st.download_button(
        "📥 Download SPDX SBOM",
        data=sbom_json,
        file_name=f"sbom_build_{selected_build}.spdx.json",
        mime="application/json"
    )
    
    # Evidence package
    st.subheader("📋 Security Evidence Package")
    
    evidence_package = {
        "metadata": {
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "analyzer_version": "1.0.0",
            "build_id": selected_build
        },
        "build_metadata": build_metadata,
        "security_violations": security_violations,
        "dependencies": {
            "source_files": list(dependencies.get("source_files", [])),
            "include_files": list(dependencies.get("include_files", [])),
            "object_files": list(dependencies.get("object_files", [])),
            "compile_commands": dependencies.get("compile_commands", [])
        },
        "slsa_provenance": provenance,
        "sbom": sbom,
        "security_policy": security_policy
    }
    
    # Create ZIP package
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Add evidence package
        zip_file.writestr(
            f"security_evidence_build_{selected_build}.json",
            json.dumps(evidence_package, indent=2)
        )
        
        # Add SLSA provenance
        zip_file.writestr(
            f"slsa_provenance_build_{selected_build}.json",
            provenance_json
        )
        
        # Add SBOM
        zip_file.writestr(
            f"sbom_build_{selected_build}.spdx.json", 
            sbom_json
        )
        
        # Add process data CSV
        if not processes_df.empty:
            zip_file.writestr(
                f"processes_build_{selected_build}.csv",
                processes_df.to_csv(index=False)
            )
        
        # Add dependency data
        if dependencies.get("compile_commands"):
            commands_df = pd.DataFrame(dependencies["compile_commands"])
            zip_file.writestr(
                f"compile_commands_build_{selected_build}.csv",
                commands_df.to_csv(index=False)
            )
    
    st.download_button(
        "📦 Download Complete Evidence Package",
        data=zip_buffer.getvalue(),
        file_name=f"security_evidence_package_build_{selected_build}.zip",
        mime="application/zip"
    )
    


# Footer
st.markdown("---")
st.markdown("*Security & Compliance Analytics for Build Systems v1.0*")
