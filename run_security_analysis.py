#!/usr/bin/env python3
"""
Demo script to run the security analytics app with sample data.

This script:
1. Runs the ingest script to populate DuckDB
2. Launches the security analytics Streamlit app
3. Provides usage examples and guidance

Usage:
    python3 run_security_analysis.py [--ingest] [--app]
"""

import argparse
import subprocess
import sys
from pathlib import Path


def run_ingest():
    """Run the DuckDB ingest script."""
    print("🔄 Running DuckDB ingest...")
    
    ingest_script = Path("scripts/ingest_duckdb.py")
    if not ingest_script.exists():
        print("❌ Error: Ingest script not found at scripts/ingest_duckdb.py")
        return False
    
    try:
        result = subprocess.run([
            sys.executable, str(ingest_script), 
            "--verbose", 
            "--output", "build_analytics.duckdb"
        ], check=True, capture_output=True, text=True)
        
        print("✅ DuckDB ingest completed successfully!")
        print(f"Output: {result.stdout}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running ingest script: {e}")
        print(f"Error output: {e.stderr}")
        return False


def run_security_app():
    """Launch the security analytics Streamlit app."""
    print("🚀 Launching Security Analytics App...")
    
    security_app = Path("security_app.py")
    if not security_app.exists():
        print("❌ Error: Security app not found at security_app.py")
        return False
    
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", 
            str(security_app),
            "--server.port", "8502",
            "--server.headless", "false"
        ], check=True)
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running security app: {e}")
        return False
    except KeyboardInterrupt:
        print("\n👋 Security app stopped by user")
        return True


def print_usage_guide():
    """Print usage guide and examples."""
    print("""
📖 Security Analytics App Usage Guide
=====================================

🎯 Key Features:
- Security & compliance analysis of build data
- SLSA Level 1 provenance generation
- SPDX SBOM (Software Bill of Materials) creation
- Interactive dependency graph visualization
- Build artifact integrity verification
- Supply chain security analysis

🔧 Prerequisites:
1. Install dependencies: pip install -r requirements.txt
2. Run data ingest: python3 scripts/ingest_duckdb.py
3. Ensure you have SQLite databases in data/sqlite/
4. Ensure you have ccache logs in data/ccache/

🚀 How to Use:
1. Select your DuckDB file (default: build_analytics.duckdb)
2. Configure security policies in the sidebar
3. Choose a build to analyze
4. Click "Run Security Analysis"
5. Review security findings and compliance reports
6. Download SLSA provenance and SBOM documents

📊 What You'll Get:
- Security violation reports
- Dependency analysis and graphs
- SLSA Level 1 provenance documents
- SPDX SBOM files
- Complete evidence packages for compliance

🔐 Security Policies:
- Customizable via YAML in the sidebar
- Checks for denied processes (curl, wget, etc.)
- Validates build duration limits
- Monitors suspicious compiler flags
- Tracks external dependencies

💾 Downloads Available:
- SLSA Provenance (JSON)
- SPDX SBOM (JSON)
- Security Evidence Package (ZIP)
- Process execution data (CSV)
- Dependency analysis (CSV)

🌐 Access the app at: http://localhost:8502
""")


def main():
    parser = argparse.ArgumentParser(
        description="Run security analytics demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 run_security_analysis.py --ingest --app    # Run ingest then app
  python3 run_security_analysis.py --app             # Just run the app
  python3 run_security_analysis.py                   # Show usage guide
        """
    )
    parser.add_argument(
        "--ingest", 
        action="store_true",
        help="Run the DuckDB ingest script first"
    )
    parser.add_argument(
        "--app", 
        action="store_true", 
        help="Launch the security analytics app"
    )
    
    args = parser.parse_args()
    
    if not args.ingest and not args.app:
        print_usage_guide()
        return
    
    success = True
    
    if args.ingest:
        success = run_ingest()
        if not success:
            print("❌ Ingest failed, stopping.")
            return
    
    if args.app and success:
        run_security_app()


if __name__ == "__main__":
    main()

