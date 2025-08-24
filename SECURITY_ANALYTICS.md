# Security & Compliance Analytics

A comprehensive security analysis tool for build systems that provides SLSA Level 1 compliance, SBOM generation, and supply chain security insights.

## 🎯 Features

### Security Analysis
- **Policy Violation Detection**: Identifies unauthorized processes, suspicious flags, and compliance violations
- **Supply Chain Security**: Analyzes build dependencies and external components
- **Build Integrity Verification**: Validates build processes against security policies
- **Risk Assessment**: Evaluates security posture and potential vulnerabilities

### SLSA Level 1 Compliance
- **Provenance Generation**: Creates SLSA v1.0 provenance documents
- **Build Metadata**: Captures comprehensive build environment details
- **Artifact Tracking**: Links build outputs to their source materials
- **Attestation Support**: Compatible with in-toto and witness frameworks

### SBOM Generation
- **SPDX 2.3 Format**: Industry-standard Software Bill of Materials
- **Dependency Tracking**: Complete inventory of source files and dependencies
- **License Information**: Placeholder structure for license compliance
- **Relationship Mapping**: Documents component dependencies and relationships

### Dependency Analysis
- **Interactive Graphs**: Visual dependency networks from ccache logs
- **File Relationships**: Source-to-header dependency mapping
- **Hotspot Identification**: Finds highly connected components
- **Build Impact Analysis**: Identifies critical dependencies

## 🚀 Quick Start

### 1. Prerequisites

```bash
# Install dependencies
pip install -r requirements.txt

# Ensure data is available
ls data/sqlite/    # Should contain *.db files
ls data/ccache/    # Should contain log files
```

### 2. Data Ingestion

```bash
# Run the ingest script to populate DuckDB
python3 scripts/ingest_duckdb.py --verbose
```

### 3. Launch Security App

```bash
# Option 1: Direct launch
streamlit run security_app.py --server.port 8502

# Option 2: Using demo script
python3 run_security_analysis.py --app

# Option 3: Full pipeline
python3 run_security_analysis.py --ingest --app
```

### 4. Access the Application

Open your browser to: http://localhost:8502

## 📊 Application Overview

### Main Dashboard
- **Build Overview**: Key metrics and status indicators
- **Security Findings**: Policy violations and risk assessments
- **Dependency Analysis**: File relationships and build dependencies
- **Compliance Reports**: SLSA provenance and SBOM documents

### Security Policy Configuration
```yaml
# Configurable via sidebar YAML editor
allowed_include_roots:
  - "/project"
  - "/usr/include"
  - "/opt"
  - "/usr/lib/clang"

denied_processes:
  - "curl"
  - "wget"
  - "apt"
  - "dnf"
  - "pip"
  - "npm"
  - "git"
  - "svn"

suspicious_flags:
  - "-fplugin="
  - "-Xclang -load"
  - " -B "
  - "-Wl,--wrap"
  - "-Wl,-rpath"
  - "LD_PRELOAD="
  - "DYLD_INSERT_LIBRARIES="

max_build_duration_hours: 24
```

## 🔍 Analysis Capabilities

### Security Violations

1. **Denied Processes**: Detects unauthorized tools (package managers, VCS, etc.)
2. **Suspicious Flags**: Identifies potentially dangerous compiler/linker flags
3. **Build Duration**: Monitors for unusually long build times
4. **External Access**: Tracks network and external resource usage

### Dependency Analysis

1. **Source Files**: Complete inventory of compiled source code
2. **Header Dependencies**: Include file relationships and hierarchies
3. **Object Files**: Build output tracking and verification
4. **Compile Commands**: Full command-line analysis for each compilation unit

### Compliance Reporting

1. **SLSA Provenance**: JSON documents containing:
   - Build definition and parameters
   - Execution metadata (start/end times, builder info)
   - Material dependencies (source files, headers)
   - Build artifacts (object files, executables)

2. **SPDX SBOM**: JSON documents containing:
   - Package inventory with relationships
   - File-level dependency tracking
   - License and copyright placeholders
   - Supply chain component mapping

## 📥 Output Formats

### Individual Downloads
- `slsa_provenance_build_X.json` - SLSA v1.0 provenance document
- `sbom_build_X.spdx.json` - SPDX 2.3 SBOM document
- `processes_build_X.csv` - Process execution data
- `compile_commands_build_X.csv` - Compilation command analysis

### Evidence Package (ZIP)
Contains all individual files plus:
- `security_evidence_build_X.json` - Complete security analysis
- Summary reports and metadata
- Policy configuration used for analysis

## 🔧 Configuration

### DuckDB Database
- Default path: `build_analytics.duckdb`
- Created by: `scripts/ingest_duckdb.py`
- Contains: SQLite table data + ccache logs

### Security Policies
- Editable via sidebar YAML configuration
- Real-time policy validation
- Customizable violation thresholds
- Extensible rule framework

### Visualization Settings
- Interactive dependency graphs (Plotly)
- Configurable node/edge limits for performance
- Color-coded file types and relationships
- Responsive layout for different screen sizes

## 🛡️ Security Considerations

### Data Privacy
- All analysis runs locally
- No external data transmission
- Build data remains on your system
- Configurable sensitive data filtering

### Performance
- Optimized for large build datasets
- Progressive loading for complex graphs
- Memory-efficient data processing
- Scalable visualization limits

### Compliance
- SLSA v1.0 specification compliance
- SPDX 2.3 standard compatibility
- Industry best practices implementation
- Audit trail generation

## 🔍 Advanced Usage

### Custom Security Policies

```python
# Example: Custom policy validation
def custom_security_check(processes_df, policy):
    violations = []
    
    # Check for specific process patterns
    for _, proc in processes_df.iterrows():
        if "malicious_pattern" in proc.get("process_name", ""):
            violations.append({
                "type": "custom_violation",
                "process": proc.get("process_name"),
                "severity": "critical"
            })
    
    return violations
```

### Integration with CI/CD

```bash
# Example: Automated security analysis
#!/bin/bash
python3 scripts/ingest_duckdb.py --mode=replace
python3 -c "
import json
from security_app import generate_slsa_provenance, analyze_security_violations
# ... run analysis programmatically
"
```

### Witness Framework Integration

```bash
# Generate attestations with witness
witness in-toto attest \
  --predicate slsa_provenance_build_X.json \
  --type https://slsa.dev/provenance/v1 \
  --output build_attestation.dsse \
  --signer file://path/to/signing/key
```

## 📚 API Reference

### Core Functions

```python
# Load and analyze build data
conn = load_duckdb_connection("build_analytics.duckdb")
builds = get_available_builds(conn)
metadata = get_build_metadata(conn, build_id)
processes = get_process_data(conn, build_id)

# Security analysis
violations = analyze_security_violations(processes, policy)
dependencies = parse_ccache_dependencies(ccache_data)

# Compliance reporting
provenance = generate_slsa_provenance(metadata, processes, dependencies)
sbom = generate_sbom(metadata, dependencies)

# Visualization
graph_fig = create_dependency_graph_plot(dependencies)
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Update documentation
5. Submit pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙋 Support

For questions or issues:
1. Check existing documentation
2. Review example configurations
3. Open GitHub issue with details
4. Include relevant log output

---

**Built for secure, compliant, and auditable build processes** 🔐

