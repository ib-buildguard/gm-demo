# 🔒 Build Evidence & Security Analysis Tool

A comprehensive, production-quality Streamlit application for analyzing IncrediBuild SQLite databases and ccache logs to generate security and compliance insights.

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
streamlit run app.py
```

## ✨ Key Features

### 🔍 **Enhanced Security Analysis**
- **Network/Package Detection**: Identifies suspicious network activities (curl, wget, pip, npm, apt)
- **Compiler Flag Analysis**: Detects dangerous compiler/linker flags that could enable code injection
- **Workspace Boundary Enforcement**: Monitors processes running outside designated workspaces
- **Process Drift Detection**: Compares builds against baselines to identify new processes

### 📊 **Advanced Visualizations**
- **Interactive Dependency Graphs**: NetworkX-powered dependency visualization
- **Process Tree Graphs**: Hierarchical process execution relationships  
- **Calendar Heatmaps**: Build activity patterns over time
- **DuckDB Analytics**: Advanced SQL analytics for build patterns

### 🛡️ **Security Violation Explanations**
- **Detailed Risk Explanations**: Clear descriptions of why each violation is dangerous
- **Risk Level Classification**: CRITICAL, HIGH, MEDIUM risk categorization
- **Violation Categories**: Organized findings with specific explanations
- **Remediation Guidance**: Actionable insights for security improvements

### 📈 **DuckDB Integration**
- **Build Frequency Analysis**: Process count and timing patterns across builds
- **Machine Utilization**: Workload distribution across build machines
- **Process Timing Patterns**: Statistical analysis of process execution times

## 🎯 **New Features Added**

### 1. **Enhanced Violation Display**
- ✅ Comprehensive violation explanations with risk levels
- ✅ Category-based findings organization
- ✅ Expandable danger explanations
- ✅ Visual risk indicators (🔴 CRITICAL, 🟡 MEDIUM)

### 2. **Interactive Graph Visualizations**
- ✅ Header dependency network graphs (Altair-based)
- ✅ Process execution tree visualization
- ✅ Timeline-based process hierarchy charts

### 3. **DuckDB Advanced Analytics**
- ✅ SQL-based build pattern analysis
- ✅ Cross-build process comparison
- ✅ Machine utilization statistics
- ✅ Performance trend analysis

### 4. **Vulnerable Build Demo**
- ✅ Example SQLite database with security violations
- ✅ Realistic vulnerability scenarios for testing
- ✅ Demonstration of all security detection capabilities

### 5. **Calendar Heatmap**
- ✅ Build activity visualization over time
- ✅ Failed build tracking
- ✅ Build frequency patterns
- ✅ Recent activity summaries

## 📦 **Data Sources**

### Required Files
```
data/
├── sqlite/
│   ├── *.db                           # IncrediBuild SQLite databases
│   └── GM_Android_vulnerable_99.db    # Example vulnerable build (auto-created)
└── ccache/
    └── full_log_hot_raw_data.txt      # ccache debug logs
```

### SQLite Schema Support
- **build_history**: Build metadata and timing
- **build_*_process**: Process execution data with arguments
- **Flexible column mapping**: Handles various IncrediBuild schema versions

## 🔧 **Configuration**

### Security Policy (YAML)
```yaml
allowed_include_roots:
  - "/project"
  - "/usr/include" 
  - "/opt"
  - "/usr/lib/clang"

deny_processes:
  - "curl"
  - "wget"
  - "apt"
  - "dnf"
  - "pip"
  - "npm"

deny_flags_contains:
  - "-fplugin="
  - "-Xclang -load"
  - " -B "
  - "-Wl,--wrap"
  - "-Wl,-rpath"
  - "LD_PRELOAD="
  - "DYLD_INSERT_LIBRARIES="
```

## 📊 **Evidence Pack Output**

### JSON Report Structure
```json
{
  "metadata": {...},
  "build": {...},
  "execution_graph_fingerprint": {...},
  "security_findings": {
    "summary": {...},
    "network_pkg_activity": [...],
    "suspicious_compiler_flags": [...],
    "workspace_boundary_violations": [...],
    "process_drift_new": [...]
  },
  "dependency_analysis": {...},
  "policy_configuration": {...}
}
```

### ZIP Package Contents
```
evidence_pack_build_XX.zip
├── evidence_build_XX.json          # Main analysis report
├── data/processes.csv               # All build processes
├── findings/
│   ├── network_activity.csv         # Network violations
│   ├── suspicious_flags.csv         # Compiler flag issues
│   ├── workspace_violations.csv     # Boundary violations
│   └── process_drift.csv           # New processes
├── dependencies/
│   ├── include_roots.csv            # Header distribution
│   └── policy_violations.csv        # Policy violations
├── performance/
│   ├── top_tools.csv               # Process statistics
│   └── cache_misses.csv            # Cache performance
└── README.md                       # Documentation
```

## 🔐 **Security Focus Areas**

### 1. **Network Activity Detection**
- Package manager usage during build
- HTTP/HTTPS requests in arguments
- Download patterns and external dependencies

### 2. **Compiler Security**
- Plugin loading mechanisms
- Custom linker paths
- Runtime library injection
- Temporary directory usage

### 3. **Build Isolation**
- Workspace boundary enforcement
- Unauthorized file access
- Process execution context

### 4. **Supply Chain Security**
- Build reproducibility via EGF hashing
- Dependency policy compliance
- Process drift monitoring

## 🚀 **Usage Examples**

### Basic Analysis
1. Place IncrediBuild SQLite files in `data/sqlite/`
2. Run `streamlit run app.py`
3. Select Current and Baseline builds
4. Click "🚀 Generate Security Analysis"

### Vulnerability Demo
1. Enable "📊 Include Vulnerable Build Demo" in sidebar
2. Generate analysis to see example violations
3. Review detailed explanations and risk assessments

### Advanced Analytics
1. Enable "🕸️ Show Dependency Graphs" for visualizations
2. Enable "📅 Show Calendar Heatmap" for timeline analysis
3. Explore DuckDB analytics for cross-build insights

## 🔗 **Integration**

### CI/CD Pipeline
```yaml
# GitHub Actions example
- name: Generate Build Evidence
  run: |
    streamlit run app.py --server.headless true
    
- name: Upload Evidence
  uses: actions/upload-artifact@v3
  with:
    name: build-evidence
    path: evidence_*.json
```

### SLSA/in-toto Integration
```bash
# Generate attestation
witness in-toto attest \
  --predicate evidence_build_XX.json \
  --type https://slsa.dev/provenance/v1 \
  --output attestation.dsse
```

## 🛠️ **Architecture**

- **Single File**: Zero-infrastructure deployment
- **Streamlit UI**: Interactive web interface
- **Pandas**: Data processing and analysis
- **DuckDB**: Advanced SQL analytics
- **Altair**: Interactive visualizations
- **NetworkX**: Graph analysis
- **YAML**: Configuration management

## 📈 **Performance**

- **Scalable**: Handles large build databases efficiently
- **Memory Optimized**: Streaming data processing
- **Interactive**: Real-time analysis and visualization
- **Robust**: Comprehensive error handling

---

**Built for production security and compliance analysis of IncrediBuild environments.**
