#!/usr/bin/env python3
"""
Quick verification script for DuckDB setup
"""

import duckdb
import pandas as pd
import json
from pathlib import Path

def verify_duckdb(db_path="build_analytics.duckdb"):
    """Verify DuckDB database structure and content."""
    if not Path(db_path).exists():
        print(f"❌ Database {db_path} not found!")
        return False
    
    print(f"🔍 Verifying DuckDB database: {db_path}")
    
    try:
        conn = duckdb.connect(db_path)
        
        # Check tables
        tables = conn.execute("SHOW TABLES").df()
        print(f"📊 Found {len(tables)} tables:")
        for _, row in tables.iterrows():
            table_name = row['name']
            count = conn.execute(f"SELECT COUNT(*) as count FROM {table_name}").df().iloc[0]['count']
            print(f"   - {table_name}: {count:,} rows")
        
        # Check builds
        if 'builds' in tables['name'].values:
            builds_info = conn.execute("""
                SELECT 
                    COUNT(*) as total_builds,
                    MIN(build_id) as min_build_id,
                    MAX(build_id) as max_build_id,
                    AVG(duration_s) as avg_duration
                FROM builds
            """).df().iloc[0]
            
            print(f"\n🏗️  Build Summary:")
            print(f"   Total builds: {builds_info['total_builds']}")
            print(f"   Build ID range: {builds_info['min_build_id']} - {builds_info['max_build_id']}")
            print(f"   Average duration: {builds_info['avg_duration']:.1f}s")
        
        # Check processes
        if 'processes' in tables['name'].values:
            proc_info = conn.execute("""
                SELECT 
                    COUNT(*) as total_processes,
                    COUNT(DISTINCT process_name) as unique_processes,
                    COUNT(DISTINCT machine_name) as unique_machines
                FROM processes
            """).df().iloc[0]
            
            print(f"\n⚙️  Process Summary:")
            print(f"   Total processes: {proc_info['total_processes']:,}")
            print(f"   Unique process types: {proc_info['unique_processes']}")
            print(f"   Unique machines: {proc_info['unique_machines']}")
        
        # Check security findings
        if 'security_findings' in tables['name'].values:
            findings_info = conn.execute("""
                SELECT 
                    finding_type,
                    risk_level,
                    COUNT(*) as count
                FROM security_findings
                GROUP BY finding_type, risk_level
                ORDER BY count DESC
            """).df()
            
            if not findings_info.empty:
                print(f"\n🚨 Security Findings:")
                for _, row in findings_info.iterrows():
                    print(f"   {row['finding_type']} ({row['risk_level']}): {row['count']}")
            else:
                print(f"\n✅ No security findings detected")
        
        conn.close()
        print(f"\n✅ Database verification completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error verifying database: {e}")
        return False

def verify_export(export_path="analytics_export.json"):
    """Verify export file."""
    if not Path(export_path).exists():
        print(f"❌ Export file {export_path} not found!")
        return False
    
    print(f"\n📄 Verifying export file: {export_path}")
    
    try:
        with open(export_path) as f:
            data = json.load(f)
        
        print(f"   Timestamp: {data.get('timestamp', 'N/A')}")
        print(f"   Summary sections: {len(data.get('summary', {}))}")
        print(f"   Detailed data tables: {len(data.get('detailed_data', {}))}")
        
        if 'summary' in data:
            summary = data['summary']
            if 'builds' in summary:
                print(f"   Total builds: {summary['builds'].get('total_builds', 0)}")
            if 'processes' in summary:
                print(f"   Total processes: {summary['processes'].get('total_processes', 0)}")
        
        print(f"✅ Export file verification completed!")
        return True
        
    except Exception as e:
        print(f"❌ Error verifying export: {e}")
        return False

if __name__ == "__main__":
    print("🔍 DuckDB Verification Tool")
    print("=" * 40)
    
    db_ok = verify_duckdb()
    export_ok = verify_export()
    
    print("\n" + "=" * 40)
    if db_ok and export_ok:
        print("🎉 All verifications passed!")
    else:
        print("❌ Some verifications failed!")
        if not db_ok:
            print("   - DuckDB verification failed")
        if not export_ok:
            print("   - Export verification failed")
