#!/usr/bin/env python3
"""
Security & Compliance Analytics for Build Data (Streamlit)
Enterprise Dashboard v4: Focused, minimal, decision-oriented interface.
Progressive disclosure: actions first, evidence as needed.

Deployment:
- Set MOTHERDUCK_TOKEN environment variable to use cloud database
- Set MOTHERDUCK_DATABASE environment variable (defaults to "build_analytics")
- Without environment variables, falls back to local build_analytics.duckdb
"""

import json
import hashlib
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Union, Optional

import streamlit as st
import pandas as pd
import networkx as nx  # kept for future use
import duckdb
import yaml
import plotly.express as px
import plotly.graph_objects as go

# =========================
# Constants & Helpers
# =========================
DEFAULT_DUCKDB_PATH = "build_analytics.duckdb"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SPDX_VERSION = "SPDX-2.3"

DEFAULT_SECURITY_POLICY = {
    "denied_processes": ["curl", "wget", "apt", "dnf", "pip", "npm", "git", "svn"],
    "suspicious_flags": ["-fplugin=", "-Xclang -load", " -B ", "-Wl,--wrap", "-Wl,-rpath", "LD_PRELOAD=", "DYLD_INSERT_LIBRARIES="],
    "max_cpu_spike_threshold": 10000,
    "max_process_count_delta": 50
}

EXPLANATIONS = {
    "NETWORK_ACCESS": "Process accesses external networks/URLs during build. Risk: dependency tampering or data exfiltration.",
    "REMOTE_EXEC": "Flags indicate remote code execution or loading external code. Risk: arbitrary code execution.",
    "PRIVILEGE_ESCALATION": "Process requested elevated privileges. Risk: privilege escalation.",
    "DESTRUCTIVE": "Arguments suggest destructive file operations. Risk: data loss.",
    "SUSPICIOUS_CONFIG": "Configuration flags that could be suspicious but aren't immediately dangerous. Risk: potential abuse.",
}

st.set_page_config(
    page_title="Security Analytics",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="🛡️",
)

# ---------- Utility ----------
def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def truncate_text(text: str, max_length: int = 120) -> str:
    """Truncate text to specified length with ellipsis."""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

# ---------- Connections ----------

def load_duckdb_connection(db_path: str) -> Optional[duckdb.DuckDBPyConnection]:
    try:
        return duckdb.connect(db_path)
    except Exception as e:
        st.error(f"❌ Database connection failed: {e}")
        return None

# ---------- Data Access ----------

def get_available_builds(conn: duckdb.DuckDBPyConnection) -> pd.DataFrame:
    try:
        tables_result = conn.execute("SHOW TABLES").fetchall()
        build_tables = [t[0] for t in tables_result if t[0].startswith('sqlite_build_')]
        build_ids = set()
        import re
        for table in build_tables:
            m = re.search(r"sqlite_build_(\d+)_", table)
            if m:
                build_ids.add(int(m.group(1)))
        rows = []
        for bid in sorted(build_ids):
            try:
                c = conn.execute(f"SELECT COUNT(*) FROM sqlite_build_{bid}_intercepted_process").fetchone()[0]
            except Exception:
                c = 0
            rows.append({"build_id": bid, "process_count": c})
        return pd.DataFrame(rows)
    except Exception as e:
        st.error(f"Failed to load builds: {e}")
        return pd.DataFrame()

def get_build_metadata(conn: duckdb.DuckDBPyConnection, build_id: str) -> Dict:
    try:
        q = """
        SELECT * FROM sqlite_build_history 
        WHERE _source_build_id = ? 
        ORDER BY BuildId DESC LIMIT 1
        """
        df = conn.execute(q, [build_id]).df()
        if df.empty:
            return {}
        row = df.iloc[0]
        md = {
            "build_id": str(row.get("BuildId", build_id)),
            "caption": str(row.get("BuildCaption", "")),
            "working_dir": str(row.get("WorkingDir", "")),
            "build_command": str(row.get("BuildCommand", "")),
            "start_time": int(row.get("StartTime", 0)),
            "end_time": int(row.get("EndTime", 0)),
            "return_code": int(row.get("ReturnCode", 0)),
        }
        if md["end_time"] and md["start_time"]:
            md["duration_ms"] = md["end_time"] - md["start_time"]
        return md
    except Exception as e:
        st.error(f"Failed to load build metadata: {e}")
        return {}

def get_process_data(conn: duckdb.DuckDBPyConnection, build_id: str) -> pd.DataFrame:
    try:
        q = f"""
        SELECT 
            PID as process_id,
            ProcessName,
            Start as start_time,
            "End" as end_time,
            cpu_time_ms,
            max_memory_kb,
            duration_ms,
            cpu_spike_flag,
            working_dir,
            Arguments as arguments
        FROM cpu_spike_analysis
        WHERE build_id = '{build_id}'
        ORDER BY cpu_time_ms DESC
        """
        return conn.execute(q).df()
    except Exception as e:
        st.error(f"Failed to load process data: {e}")
        return pd.DataFrame()

def get_toolchain_data(conn: duckdb.DuckDBPyConnection, build_id: str) -> Dict:
    try:
        tools_q = f"""
        SELECT 
            tool_name as ProcessName,
            usage_count,
            unique_locations as unique_directories,
            avg_duration_ms,
            total_cpu_time_ms,
            avg_cpu_time_ms,
            max_cpu_time_ms,
            max_memory_kb,
            tool_category
        FROM toolchain_performance_summary
        WHERE build_id = '{build_id}'
        ORDER BY usage_count DESC
        """
        tools_df = conn.execute(tools_q).df()

        args_q = f"""
        SELECT ProcessName, Arguments, security_flag, risk_score, working_dir
        FROM suspicious_arguments
        WHERE build_id = '{build_id}' AND security_flag != 'NORMAL'
        ORDER BY risk_score DESC
        """
        args_df = conn.execute(args_q).df()

        return {"toolchains": tools_df, "suspicious_args": args_df}
    except Exception as e:
        st.error(f"Failed to analyze toolchain data: {e}")
        return {"toolchains": pd.DataFrame(), "suspicious_args": pd.DataFrame()}

# ---------- Heuristic Real-Process Analyzer ----------

def analyze_real_scenarios(conn: duckdb.DuckDBPyConnection, build_id: str, security_policy: Dict) -> pd.DataFrame:
    """
    Scan the intercepted processes table and derive suspicious findings
    even if the precomputed suspicious_arguments view is empty.
    Returns columns: ProcessName, Arguments, security_flag, risk_score, working_dir, source.
    """
    try:
        q = f"""
        SELECT 
            COALESCE(ProcessName, process_name) AS ProcessName,
            COALESCE(Arguments, args, command_line) AS Arguments,
            COALESCE(WorkingDir, working_dir, Cwd) AS working_dir
        FROM sqlite_build_{build_id}_intercepted_process
        """
        df = conn.execute(q).df()
    except Exception:
        return pd.DataFrame(columns=["ProcessName", "Arguments", "security_flag", "risk_score", "working_dir", "source"])

    if df.empty:
        return pd.DataFrame(columns=["ProcessName", "Arguments", "security_flag", "risk_score", "working_dir", "source"])

    df["ProcessName"] = df["ProcessName"].fillna("")
    df["Arguments"]   = df["Arguments"].fillna("")
    if "working_dir" not in df.columns:
        df["working_dir"] = None

    findings = []
    denied = [d.lower() for d in security_policy.get("denied_processes", [])]

    def add(proc, args, flag, score, wd, reason):
        findings.append({
            "ProcessName": proc,
            "Arguments": args,
            "security_flag": flag,
            "risk_score": int(score),
            "working_dir": wd,
            "source": reason
        })

    # Track what we've already found to avoid duplicates
    found_patterns = set()
    
    for _, row in df.iterrows():
        proc = str(row["ProcessName"]) or ""
        args = str(row["Arguments"]) or ""
        wd   = row.get("working_dir")
        lp   = proc.lower()
        la   = args.lower()

        # 1) Denylist hits - only add if we haven't seen this tool + pattern
        if any(d in lp for d in denied):
            pattern_key = (proc, "denylist")
            if pattern_key not in found_patterns:
                add(proc, args, "NETWORK_ACCESS" if any(x in lp for x in ["curl","wget","git"]) else "DESTRUCTIVE", 7, wd, "denylist")
                found_patterns.add(pattern_key)

        # 2) Network access patterns - only add if we haven't seen this tool + pattern
        if "http://" in la or "https://" in la or any(x in lp for x in ["curl","wget","git"]):
            pattern_key = (proc, "NETWORK_ACCESS")
            if pattern_key not in found_patterns:
                add(proc, args, "NETWORK_ACCESS", 7, wd, "url/tool")
                found_patterns.add(pattern_key)

        # 3) Dynamic/remote code loading - ONLY flag patterns that can actually execute arbitrary code
        # These are the ONLY flags that pose real remote execution risks
        remote_exec_patterns = [
            "-fplugin=",           # Load external plugin (can execute code)
            "-Xclang -load",       # Load dynamic library (can execute code)
            " ld_preload",         # Preload library (can execute code)
            "dyld_insert_libraries=", # macOS library injection (can execute code)
        ]
        
        if any(pattern in la for pattern in remote_exec_patterns):
            pattern_key = (proc, "REMOTE_EXEC")
            if pattern_key not in found_patterns:
                core_tool = any(x in lp for x in ["clang", "gcc", "ld"])
                add(proc, args, "REMOTE_EXEC", 9 if core_tool else 8, wd, "loader/plugin")
                found_patterns.add(pattern_key)

        # 4) Privilege escalation - only add if we haven't seen this tool + pattern
        if proc == "sudo" or " sudo " in (" " + la) or "chmod 777" in la or "chown " in la:
            pattern_key = (proc, "PRIVILEGE_ESCALATION")
            if pattern_key not in found_patterns:
                add(proc, args, "PRIVILEGE_ESCALATION", 8, wd, "elevated")
                found_patterns.add(pattern_key)

        # 5) Destructive ops - only add if we haven't seen this tool + pattern
        if "rm -rf" in la or "del /s" in la or "rmdir /s" in la:
            pattern_key = (proc, "DESTRUCTIVE")
            if pattern_key not in found_patterns:
                add(proc, args, "DESTRUCTIVE", 8, wd, "destructive")
                found_patterns.add(pattern_key)

        # 6) Package managers during build - only add if we haven't seen this tool + pattern
        if any(pm in lp for pm in ["apt", "dnf", "yum", "pip", "npm", "pnpm", "bundler", "gem"]):
            pattern_key = (proc, "NETWORK_ACCESS")
            if pattern_key not in found_patterns:
                add(proc, args, "NETWORK_ACCESS", 7, wd, "pkg-manager")
                found_patterns.add(pattern_key)
        
        # 7) Suspicious but not dangerous - lower risk flags that need review
        # These could potentially be abused but aren't immediately dangerous
        if any(flag in la for flag in [
            "-B /tmp",             # Search path in temp (suspicious location)
            "-B /var/tmp",         # Search path in var/tmp (suspicious location)
            "-L/tmp",              # Library path in temp
            "-I/tmp",              # Include path in temp
            "-Wl,--wrap",          # Function wrapping (could be abused)
            "-Wl,-rpath",          # Runtime path (could be suspicious)
        ]):
            pattern_key = (proc, "SUSPICIOUS_CONFIG")
            if pattern_key not in found_patterns:
                add(proc, args, "SUSPICIOUS_CONFIG", 5, wd, "suspicious-config")
                found_patterns.add(pattern_key)

    if findings:
        # Create unique findings by ProcessName + security_flag combination
        unique_findings = {}
        for finding in findings:
            key = (finding["ProcessName"], finding["security_flag"])
            if key not in unique_findings or finding["risk_score"] > unique_findings[key]["risk_score"]:
                unique_findings[key] = finding
        
        return pd.DataFrame(list(unique_findings.values()))
    else:
        return pd.DataFrame(columns=["ProcessName","Arguments","security_flag","risk_score","working_dir","source"])

# ---------- Action Items Logic ----------

def derive_action_items(
    susp_args_df: pd.DataFrame, 
    new_tools: List[str], 
    removed_tools: List[str], 
    proc_count_delta: int,
    high_cpu_processes: pd.DataFrame,
    security_policy: Dict
) -> List[Dict]:
    """Derive prioritized action items from security analysis."""
    actions = []
    
    # High-risk suspicious flags on critical tools - ensure unique per tool + flag combination
    if not susp_args_df.empty:
        high_risk_args = susp_args_df[susp_args_df['risk_score'] >= 8]
        critical_tools = high_risk_args[high_risk_args['ProcessName'].str.contains('clang|gcc|ld|make', case=False, na=False)]
        
        if not critical_tools.empty:
            # Group by ProcessName + security_flag to avoid duplicates
            unique_critical_findings = critical_tools.groupby(['ProcessName', 'security_flag']).first().reset_index()
            
            for _, row in unique_critical_findings.head(3).iterrows():
                actions.append({
                    "title": f"Investigate {row['security_flag'].lower()} in {row['ProcessName']}",
                    "severity": "High",
                    "why": f"Found {row['security_flag']} with risk score {row['risk_score']}/10",
                    "fix": "Review build scripts and enforce security policy restrictions",
                    "owner": "BuildSec",
                    "due": "T+2 days",
                    "evidence_ref": "#security-tab"
                })
    
    # New tools matching denylist
    denied_procs = security_policy.get("denied_processes", [])
    risky_new_tools = [t for t in new_tools if any(denied in t.lower() for denied in denied_procs)]
    if risky_new_tools:
        actions.append({
            "title": f"Review {len(risky_new_tools)} new denied processes",
            "severity": "High",
            "why": f"New tools match security denylist: {', '.join(risky_new_tools[:2])}",
            "fix": "Remove from build or add policy exception with justification",
            "owner": "DevOps",
            "due": "T+1 day",
            "evidence_ref": "#drift-analysis"
        })
    
    # Large process count increase
    if abs(proc_count_delta) > security_policy.get("max_process_count_delta", 50):
        severity = "High" if proc_count_delta > 100 else "Medium"
        actions.append({
            "title": f"Investigate process count spike (+{proc_count_delta})",
            "severity": severity,
            "why": f"Process count increased by {proc_count_delta}, indicating potential issues",
            "fix": "Review build changes and validate new processes are legitimate",
            "owner": "BuildSec",
            "due": "T+3 days",
            "evidence_ref": "#drift-analysis"
        })
    
    # CPU spikes
    if not high_cpu_processes.empty and len(high_cpu_processes) > 5:
        actions.append({
            "title": f"Review {len(high_cpu_processes)} CPU-intensive processes",
            "severity": "Medium",
            "why": f"Multiple processes with abnormal CPU usage detected",
            "fix": "Analyze process arguments and working directories for legitimacy",
            "owner": "Platform",
            "due": "T+5 days",
            "evidence_ref": "#performance-tab"
        })
    
    # Network access patterns
    if not susp_args_df.empty:
        network_access = susp_args_df[susp_args_df['security_flag'] == 'NETWORK_ACCESS']
        if not network_access.empty:
            actions.append({
                "title": f"Audit {len(network_access)} network access patterns",
                "severity": "Medium",
                "why": "Build processes accessing external networks during compilation",
                "fix": "Validate external dependencies and consider air-gapped builds",
                "owner": "SecOps",
                "due": "T+7 days",
                "evidence_ref": "#security-tab"
            })
    
    # Sort by severity priority
    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    actions.sort(key=lambda x: severity_order.get(x["severity"], 3))
    
    return actions

# ---------- Evidence Generators ----------

def generate_slsa_provenance(build_metadata: Dict, tool_names: List[str]) -> Dict:
    prov = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": SLSA_PREDICATE_TYPE,
        "subject": [],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/slsa-framework/slsa/tree/main/docs/provenance/schema",
                "externalParameters": {
                    "buildCommand": build_metadata.get("build_command", ""),
                    "workingDirectory": build_metadata.get("working_dir", ""),
                    "buildCaption": build_metadata.get("caption", ""),
                },
                "internalParameters": {
                    "buildId": build_metadata.get("build_id", ""),
                    "returnCode": build_metadata.get("return_code", 0),
                },
                "resolvedDependencies": [
                    {"uri": t, "digest": {"sha256": sha256_hex(t)}} for t in tool_names
                ],
            },
            "runDetails": {
                "builder": {"id": "https://github.com/incredibuild/build-analytics"},
                "metadata": {
                    "invocationId": sha256_hex(str(build_metadata.get("build_id", ""))),
                    "startedOn": datetime.fromtimestamp(build_metadata.get("start_time", 0)/1000, tz=timezone.utc).isoformat() if build_metadata.get("start_time") else None,
                    "finishedOn": datetime.fromtimestamp(build_metadata.get("end_time", 0)/1000, tz=timezone.utc).isoformat() if build_metadata.get("end_time") else None,
                },
            },
        },
    }
    return prov

def generate_sbom(build_metadata: Dict, tools_df: pd.DataFrame) -> Dict:
    doc_id = f"SPDXRef-DOCUMENT-{build_metadata.get('build_id','unknown')}"
    sbom = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_id,
        "documentName": f"Build SBOM for {build_metadata.get('caption','Unknown Build')}",
        "documentNamespace": f"https://build-analytics/{build_metadata.get('build_id','unknown')}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": ["Tool: build-analytics-demo"],
        },
        "packages": [],
        "relationships": [],
    }
    
    # Root package
    sbom["packages"].append({
        "SPDXID": "SPDXRef-Package-Build",
        "name": build_metadata.get("caption", "Build Package"),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
    })
    
    # Add tools as packages with demo versions
    for i, row in tools_df.iterrows():
        name = str(row.get("ProcessName", "unknown"))
        pkg_id = f"SPDXRef-Package-Tool-{i}"
        sbom["packages"].append({
            "SPDXID": pkg_id,
            "name": name,
            "versionInfo": "0.0.0-demo",
            "downloadLocation": "NOASSERTION",
            "supplier": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [],
        })
        sbom["relationships"].append({
            "spdxElementId": "SPDXRef-Package-Build",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": pkg_id,
        })
    
    return sbom

# ---------- Demo CVE helper ----------

DEMO_CVE_MAP = {
    "clang": [
        {"cve": "CVE-2024-CLANG-DEMO", "severity": "HIGH", "note": "Demo CVE for presentation only"}
    ],
    "gcc": [
        {"cve": "CVE-2023-GCC-DEMO", "severity": "MEDIUM", "note": "Demo CVE for presentation only"}
    ],
}

def related_demo_cves(tool_names: List[str]) -> pd.DataFrame:
    rows = []
    for t in tool_names:
        key = t.lower()
        for k, items in DEMO_CVE_MAP.items():
            if k in key:
                for it in items:
                    rows.append({"tool": t, **it})
    return pd.DataFrame(rows)

# =========================
# Sidebar Configuration
# =========================

st.sidebar.title("Configuration")

# Check for MotherDuck environment variables, fallback to local database
motherduck_token = os.getenv("MOTHERDUCK_TOKEN")
motherduck_database = os.getenv("MOTHERDUCK_DATABASE", "build_analytics")

if motherduck_token:
    # Use MotherDuck if token is provided
    db_path = f"md:{motherduck_database}?motherduck_token={motherduck_token}"
    st.sidebar.info("🔗 Connected to MotherDuck cloud database")
else:
    # Fallback to local database
    db_path = DEFAULT_DUCKDB_PATH
    st.sidebar.info("💾 Using local DuckDB database")

conn = load_duckdb_connection(db_path)
if not conn:
    st.stop()

builds_df = get_available_builds(conn)
if builds_df.empty:
    st.warning("No builds found in the database.")
    st.stop()

selected_build = st.sidebar.selectbox(
    "Select Build",
    options=builds_df["build_id"].tolist(),
    format_func=lambda x: f"Build {x}",
)

baseline_build = st.sidebar.selectbox(
    "Baseline (optional)",
    options=["None"] + builds_df["build_id"].tolist(),
    index=0,
    format_func=lambda x: "No baseline" if x == "None" else f"Build {x}",
)

st.sidebar.subheader("Policy Upload")
pol_file = st.sidebar.file_uploader("Upload policy (YAML or JSON)", type=["yml", "yaml", "json"])
security_policy = DEFAULT_SECURITY_POLICY
if pol_file is not None:
    try:
        if pol_file.name.endswith((".yml", ".yaml")):
            security_policy = yaml.safe_load(pol_file.read())
        else:
            security_policy = json.loads(pol_file.read())
    except Exception as e:
        st.sidebar.error(f"Invalid policy file: {e}")

run_btn = st.sidebar.button("🔍 Analyze", type="primary")

# =========================
# Main Dashboard
# =========================

# 0. Header
st.title("Build Security Command Center")
st.caption("Prioritized risks, drift highlights, and verifiable evidence for each build.")

if not run_btn:
    st.info("Configure options on the left and click **Analyze**.")
    st.stop()

# Load all data
build_md = get_build_metadata(conn, selected_build)
proc_df = get_process_data(conn, selected_build)
tc = get_toolchain_data(conn, selected_build)
tools_df = tc["toolchains"]
susp_args_df = tc["suspicious_args"]

# Enrich/replace with real-process heuristics
heuristic_df = analyze_real_scenarios(conn, selected_build, security_policy)
if not heuristic_df.empty:
    if susp_args_df.empty:
        susp_args_df = heuristic_df
    else:
        # Merge and deduplicate by ProcessName + security_flag combination
        combined_df = pd.concat([susp_args_df, heuristic_df], ignore_index=True)
        # Keep the highest risk score for each unique ProcessName + security_flag combination
        combined_df = combined_df.sort_values('risk_score', ascending=False)
        combined_df = combined_df.drop_duplicates(subset=['ProcessName', 'security_flag'], keep='first')
        susp_args_df = combined_df

# Baseline comparison data
new_tools = []
removed_tools = []
proc_count_delta = 0

if baseline_build != "None":
    base_proc = get_process_data(conn, baseline_build)
    base_tools_data = get_toolchain_data(conn, baseline_build)
    base_tools = base_tools_data["toolchains"]["ProcessName"].dropna().unique().tolist() if not base_tools_data["toolchains"].empty else []
    cur_tools = tools_df["ProcessName"].dropna().unique().tolist()
    
    new_tools = sorted(set(cur_tools) - set(base_tools))
    removed_tools = sorted(set(base_tools) - set(cur_tools))
    proc_count_delta = len(proc_df) - len(base_proc)

# High CPU processes
high_cpu_processes = proc_df[proc_df['cpu_time_ms'] > security_policy.get("max_cpu_spike_threshold", 10000)] if not proc_df.empty else pd.DataFrame()

# Derive action items
action_items = derive_action_items(
    susp_args_df, new_tools, removed_tools, proc_count_delta, high_cpu_processes, security_policy
)

# 1. Status Banner (1 line)
high_actions = [a for a in action_items if a['severity'] == 'High']
medium_actions = [a for a in action_items if a['severity'] == 'Medium']

if high_actions:
    st.error(f"🔴 **{len(high_actions)} high-priority security actions require immediate attention**")
elif medium_actions:
    st.warning(f"🟡 **{len(medium_actions)} medium-priority actions identified for review**")
else:
    st.success("🟢 **All clear** - No critical security actions required")

# 2. Key Metrics (3 compact cards)
st.subheader("Key metrics")

num_processes = len(proc_df)
num_tools = len(tools_df)
num_suspicious_tools = susp_args_df["ProcessName"].nunique() if not susp_args_df.empty else 0

k1, k2, k3 = st.columns(3)
with k1:
    st.metric("Processes Analyzed", f"{num_processes:,}")
with k2:
    st.metric("Unique Tools", f"{num_tools:,}")
with k3:
    st.metric("Suspicious Tools", f"{num_suspicious_tools:,}")

# 3. Critical Actions (max 3 cards)
st.subheader("Critical actions")

top_actions = action_items[:3]
remaining_actions = action_items[3:]

if top_actions:
    for action in top_actions:
        severity_icon = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}
        with st.container():
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"**{action['title']}** {severity_icon.get(action['severity'], '⚪')} {action['severity']}")
                st.write(f"*Why:* {truncate_text(action['why'])}")
                st.write(f"*Fix:* {truncate_text(action['fix'])}")
            with col2:
                st.write(f"**{action['owner']}**")
                st.write(f"Due: {action['due']}")
                st.link_button("Open Evidence", action['evidence_ref'])
        st.divider()
    
    if remaining_actions:
        with st.expander(f"View all actions ({len(action_items)})", expanded=False):
            for action in remaining_actions:
                severity_icon = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}
                st.write(f"**{action['title']}** {severity_icon.get(action['severity'], '⚪')} {action['severity']}")
                st.write(f"*Why:* {action['why']} | *Fix:* {action['fix']} | *Owner:* {action['owner']} | *Due:* {action['due']}")
                st.divider()
else:
    st.success("✅ No critical actions required")
    st.info("💡 Consider uploading a policy file for enhanced analysis or setting a baseline build for drift detection.")

# 4. Tabs (where details live)
st.divider()

security_tab, performance_tab, evidence_tab = st.tabs(["Security", "Performance", "Evidence"])

with security_tab:
    st.markdown('<div id="security-tab"></div>', unsafe_allow_html=True)
    
    # Filter bar
    col1, col2 = st.columns([2, 1])
    with col1:
        search_filter = st.text_input("🔍 Search tool/process", placeholder="Enter tool name or process...")
    with col2:
        severity_filter = st.selectbox("Severity", ["All", "High", "Medium", "Low"])
    
    # Policy & Drift (compact)
    st.markdown('<a id="drift-analysis"></a>', unsafe_allow_html=True)
    st.subheader("Policy & drift")
    
    if baseline_build != "None":
        d1, d2, d3 = st.columns(3)
        with d1:
            st.metric("New Tools", len(new_tools))
        with d2:
            st.metric("Removed Tools", len(removed_tools))
        with d3:
            delta_color = "normal" if abs(proc_count_delta) < 20 else "inverse"
            st.metric("Proc Count Δ", proc_count_delta, delta_color=delta_color)

        with st.expander("View details", expanded=False):
            if new_tools:
                st.write("**New tools:**")
                new_tools_df = pd.DataFrame({"ProcessName": new_tools[:20]})  # Cap to 20
                st.dataframe(new_tools_df, use_container_width=True)
            
            if removed_tools:
                st.write("**Removed tools:**")
                removed_tools_df = pd.DataFrame({"ProcessName": removed_tools[:20]})  # Cap to 20
                st.dataframe(removed_tools_df, use_container_width=True)
    else:
        st.info("Select a baseline build in the sidebar to see drift analysis.")
    
    # Suspicious Flags by Tool (curated)
    st.subheader("Suspicious flags by tool")
    
    if not susp_args_df.empty:
        # Apply filters
        filtered_df = susp_args_df.copy()
        
        if search_filter:
            mask = (filtered_df['ProcessName'].str.contains(search_filter, case=False, na=False) | 
                   filtered_df['Arguments'].str.contains(search_filter, case=False, na=False))
            filtered_df = filtered_df[mask]
        
        if severity_filter != "All":
            severity_map = {"High": 8, "Medium": 5, "Low": 1}
            min_score = severity_map.get(severity_filter, 0)
            max_score = 10 if severity_filter == "High" else (severity_map.get(severity_filter, 0) + 2)
            filtered_df = filtered_df[(filtered_df['risk_score'] >= min_score) & (filtered_df['risk_score'] <= max_score)]
        
        if not filtered_df.empty:
            # Show top 5 tools by highest risk
            top_tools = filtered_df.groupby('ProcessName')['risk_score'].max().sort_values(ascending=False).head(5)
            
            for tool_name, max_risk in top_tools.items():
                tool_findings = filtered_df[filtered_df['ProcessName'] == tool_name].head(5)  # Max 5 rows per tool
                
                with st.expander(f"{tool_name} — {len(tool_findings)} finding(s) (max risk: {max_risk})", expanded=False):
                    # Prepare display data with truncated arguments
                    display_data = tool_findings.copy()
                    display_data['Arguments'] = display_data['Arguments'].apply(lambda x: truncate_text(str(x), 120))
                    
                    st.dataframe(
                        display_data[["security_flag", "risk_score", "Arguments", "working_dir"]],
                        use_container_width=True
                    )
                    
                    # Explanations
                    flags = tool_findings["security_flag"].dropna().unique().tolist()
                    st.markdown("**What this means:**")
                    for fl in flags:
                        st.write(f"- **{fl}**: {EXPLANATIONS.get(fl, 'Potentially unsafe argument pattern detected.')}")
            
            # See all findings
            if len(filtered_df) > 25:  # Show link if more than what we display
                with st.expander("See all findings", expanded=False):
                    display_all = filtered_df.copy()
                    display_all['Arguments'] = display_all['Arguments'].apply(lambda x: truncate_text(str(x), 120))
                    st.dataframe(display_all.head(100), use_container_width=True)  # Cap to 100 rows
        else:
            st.info("No findings match the current filters.")
    else:
        st.success("No suspicious flags detected.")

with performance_tab:
    st.markdown('<div id="performance-tab"></div>', unsafe_allow_html=True)
    
    # Top Tools by Usage (bar, top 15)
    st.subheader("Top tools by usage")
    
    if not tools_df.empty:
        fig = px.bar(
            tools_df.head(15),  # Top 15 only
            x="ProcessName",
            y="usage_count",
            title="",
            labels={"usage_count": "Usage Count", "ProcessName": "Tool"},
        )
        fig.update_layout(xaxis_tickangle=-45, height=400, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No toolchain data available.")
    
    # CPU/Memory Outliers (small table, max 20 rows)
    st.subheader("CPU/Memory outliers")
    
    if not high_cpu_processes.empty:
        outliers_display = high_cpu_processes.head(20).copy()  # Max 20 rows
        outliers_display['Arguments'] = outliers_display['arguments'].apply(lambda x: truncate_text(str(x), 80))
        
        st.dataframe(
            outliers_display[["ProcessName", "cpu_time_ms", "max_memory_kb", "Arguments", "working_dir"]],
            use_container_width=True
        )
    else:
        st.success("No CPU/memory outliers detected.")

with evidence_tab:
    st.subheader("Evidence packages")
    
    tool_names = tools_df["ProcessName"].dropna().unique().tolist()
    
    # SLSA Level 1 JSON
    st.markdown("**SLSA Level 1 JSON (Demo)**")
    prov_doc = generate_slsa_provenance(build_md, tool_names)
    st.json(prov_doc)
    st.download_button(
        "Download SLSA JSON",
        data=json.dumps(prov_doc, indent=2),
        file_name=f"slsa-provenance-build-{selected_build}.json",
        mime="application/json",
        use_container_width=True,
    )
    
    st.divider()
    
    # SPDX SBOM JSON
    st.markdown("**SPDX SBOM JSON (Demo)**")
    sbom_doc = generate_sbom(build_md, tools_df)
    st.json(sbom_doc)
    st.download_button(
        "Download SBOM JSON",
        data=json.dumps(sbom_doc, indent=2),
        file_name=f"sbom-build-{selected_build}.spdx.json",
        mime="application/json",
        use_container_width=True,
    )
    
    # Related CVEs (Demo) - collapsed by default
    with st.expander("Related CVEs (Demo)", expanded=False):
        demo_cves = related_demo_cves(tool_names)
        if demo_cves.empty:
            st.info("No demo CVEs matched your tools. Add mappings in DEMO_CVE_MAP for presentations.")
        else:
            st.dataframe(demo_cves, use_container_width=True)
    
    st.info("💡 **Note:** Versions and digests may be placeholders for demo purposes.")

# 5. Footer
st.markdown("---")
st.caption("Security & Compliance Analytics — enterprise dashboard v4 (demo)")