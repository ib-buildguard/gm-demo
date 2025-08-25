#!/usr/bin/env python3
"""
Create Performance & Security Aggregated Tables
Creates smaller, pre-computed tables for fast analytics from raw build data.
"""

import duckdb
import os
import sys
from typing import List

def get_available_builds(conn: duckdb.DuckDBPyConnection) -> List[str]:
    """Get list of available builds from table names."""
    tables = conn.execute("SHOW TABLES").fetchall()
    build_ids = set()
    
    for table in tables:
        table_name = table[0]
        if table_name.startswith('sqlite_build_') and '_intercepted_process' in table_name:
            # Extract build ID from table name like 'sqlite_build_24_intercepted_process'
            parts = table_name.split('_')
            if len(parts) >= 3:
                build_ids.add(parts[2])  # Extract '24' from 'sqlite_build_24_intercepted_process'
    
    return sorted(list(build_ids))

def create_cpu_spike_analysis(conn: duckdb.DuckDBPyConnection, build_ids: List[str]):
    """Create CPU spike analysis table."""
    print("🔥 Creating CPU spike analysis table...")
    
    # Drop table if exists
    conn.execute("DROP TABLE IF EXISTS cpu_spike_analysis")
    
    # Union all builds into one table
    union_queries = []
    for build_id in build_ids:
        table_name = f"sqlite_build_{build_id}_intercepted_process"
        
        union_queries.append(f"""
        SELECT 
            '{build_id}' as build_id,
            ProcessName,
            Arguments,
            COALESCE(CAST(NULLIF(CPUtime, '') AS BIGINT), 0) as cpu_time_ms,
            COALESCE(CAST(NULLIF(MaxRSSself, '') AS BIGINT), 0) as max_memory_kb,
            COALESCE(CAST(NULLIF("End", '') AS BIGINT), 0) - COALESCE(CAST(NULLIF(Start, '') AS BIGINT), 0) as duration_ms,
            CASE 
                WHEN COALESCE(CAST(NULLIF(CPUtime, '') AS BIGINT), 0) > 10000 THEN 'HIGH_CPU'
                WHEN COALESCE(CAST(NULLIF(CPUtime, '') AS BIGINT), 0) > 5000 THEN 'MEDIUM_CPU'
                WHEN COALESCE(CAST(NULLIF(CPUtime, '') AS BIGINT), 0) > 1000 THEN 'LOW_CPU'
                ELSE 'NORMAL'
            END as cpu_spike_flag,
            Start,
            "End",
            CWD as working_dir,
            PID
        FROM {table_name}
        WHERE ProcessName IS NOT NULL
        """)
    
    create_query = f"""
    CREATE TABLE cpu_spike_analysis AS
    {' UNION ALL '.join(union_queries)}
    ORDER BY cpu_time_ms DESC
    """
    
    conn.execute(create_query)
    
    # Get stats
    stats = conn.execute("""
        SELECT 
            COUNT(*) as total_processes,
            COUNT(CASE WHEN cpu_spike_flag = 'HIGH_CPU' THEN 1 END) as high_cpu_count,
            COUNT(CASE WHEN cpu_spike_flag = 'MEDIUM_CPU' THEN 1 END) as medium_cpu_count,
            MAX(cpu_time_ms) as max_cpu_time
        FROM cpu_spike_analysis
    """).fetchone()
    
    print(f"   ✅ Created table with {stats[0]:,} processes")
    print(f"   🔥 High CPU spikes: {stats[1]:,}")
    print(f"   ⚡ Medium CPU spikes: {stats[2]:,}")
    print(f"   📊 Max CPU time: {stats[3]:,}ms")

def create_suspicious_arguments_table(conn: duckdb.DuckDBPyConnection, build_ids: List[str]):
    """Create suspicious arguments analysis table."""
    print("🚨 Creating suspicious arguments analysis table...")
    
    # Drop table if exists
    conn.execute("DROP TABLE IF EXISTS suspicious_arguments")
    
    union_queries = []
    for build_id in build_ids:
        process_table = f"sqlite_build_{build_id}_intercepted_process"
        args_table = f"sqlite_build_{build_id}_process_arguments"
        
        union_queries.append(f"""
        SELECT 
            '{build_id}' as build_id,
            ip.ProcessName,
            pa.Arguments,
            ip.CWD as working_dir,
            ip.Start,
            ip.PID,
            CASE 
                WHEN pa.Arguments LIKE '%http://%' OR pa.Arguments LIKE '%https://%' THEN 'NETWORK_ACCESS'
                WHEN pa.Arguments LIKE '%-exec%' OR pa.Arguments LIKE '%--exec%' OR pa.Arguments LIKE '%exec=%' THEN 'REMOTE_EXEC'
                WHEN pa.Arguments LIKE '%/tmp/%' OR pa.Arguments LIKE '%/var/tmp/%' THEN 'TEMP_ACCESS'
                WHEN pa.Arguments LIKE '%sudo%' OR pa.Arguments LIKE '%root%' THEN 'PRIVILEGE_ESCALATION'
                WHEN pa.Arguments LIKE '%download%' OR pa.Arguments LIKE '%wget%' OR pa.Arguments LIKE '%curl%' THEN 'DOWNLOAD'
                WHEN pa.Arguments LIKE '%rm -rf%' OR pa.Arguments LIKE '%rm -f%' THEN 'DESTRUCTIVE'
                WHEN pa.Arguments LIKE '%chmod +x%' OR pa.Arguments LIKE '%chmod 777%' THEN 'PERMISSION_CHANGE'
                WHEN pa.Arguments LIKE '%base64%' OR pa.Arguments LIKE '%decode%' THEN 'ENCODING'
                WHEN pa.Arguments LIKE '%shell%' OR pa.Arguments LIKE '%bash%' OR pa.Arguments LIKE '%sh %' THEN 'SHELL_EXECUTION'
                ELSE 'NORMAL'
            END as security_flag,
            -- Risk scoring
            CASE 
                WHEN pa.Arguments LIKE '%http://%' OR pa.Arguments LIKE '%https://%' THEN 8
                WHEN pa.Arguments LIKE '%-exec%' OR pa.Arguments LIKE '%--exec%' THEN 9
                WHEN pa.Arguments LIKE '%sudo%' OR pa.Arguments LIKE '%root%' THEN 7
                WHEN pa.Arguments LIKE '%rm -rf%' THEN 10
                WHEN pa.Arguments LIKE '%download%' OR pa.Arguments LIKE '%wget%' OR pa.Arguments LIKE '%curl%' THEN 6
                WHEN pa.Arguments LIKE '%chmod +x%' OR pa.Arguments LIKE '%chmod 777%' THEN 5
                WHEN pa.Arguments LIKE '%/tmp/%' OR pa.Arguments LIKE '%/var/tmp/%' THEN 4
                ELSE 1
            END as risk_score
        FROM {args_table} pa
        JOIN {process_table} ip ON pa.ID = ip.PID
        WHERE pa.Arguments IS NOT NULL 
        AND pa.Arguments != ''
        AND LENGTH(pa.Arguments) > 5
        """)
    
    create_query = f"""
    CREATE TABLE suspicious_arguments AS
    {' UNION ALL '.join(union_queries)}
    ORDER BY risk_score DESC, security_flag
    """
    
    conn.execute(create_query)
    
    # Get stats
    stats = conn.execute("""
        SELECT 
            COUNT(*) as total_arguments,
            COUNT(CASE WHEN security_flag != 'NORMAL' THEN 1 END) as suspicious_count,
            COUNT(CASE WHEN risk_score >= 8 THEN 1 END) as high_risk_count,
            MAX(risk_score) as max_risk_score
        FROM suspicious_arguments
    """).fetchone()
    
    print(f"   ✅ Created table with {stats[0]:,} argument entries")
    print(f"   🚨 Suspicious arguments: {stats[1]:,}")
    print(f"   ⚠️ High risk arguments: {stats[2]:,}")
    print(f"   📊 Max risk score: {stats[3]}")

def create_build_performance_summary(conn: duckdb.DuckDBPyConnection, build_ids: List[str]):
    """Create build performance summary table."""
    print("📊 Creating build performance summary table...")
    
    # Drop table if exists
    conn.execute("DROP TABLE IF EXISTS build_performance_summary")
    
    union_queries = []
    for build_id in build_ids:
        table_name = f"sqlite_build_{build_id}_intercepted_process"
        
        union_queries.append(f"""
        SELECT 
            '{build_id}' as build_id,
            COUNT(*) as total_processes,
            COUNT(DISTINCT ProcessName) as unique_tools,
            COUNT(DISTINCT CWD) as unique_directories,
            MIN(COALESCE(CAST(NULLIF(Start, '') AS BIGINT), 0)) as build_start_ts,
            MAX(COALESCE(CAST(NULLIF("End", '') AS BIGINT), 0)) as build_end_ts,
            (MAX(COALESCE(CAST(NULLIF("End", '') AS BIGINT), 0)) - MIN(COALESCE(CAST(NULLIF(Start, '') AS BIGINT), 0))) / 1000.0 / 3600.0 as duration_hours,
            SUM(COALESCE(CAST(NULLIF(CPUtime, '') AS BIGINT), 0)) as total_cpu_time_ms,
            AVG(COALESCE(CAST(NULLIF(CPUtime, '') AS BIGINT), 0)) as avg_cpu_time_ms,
            MAX(COALESCE(CAST(NULLIF(CPUtime, '') AS BIGINT), 0)) as max_cpu_time_ms,
            SUM(COALESCE(CAST(NULLIF(MaxRSSself, '') AS BIGINT), 0)) as total_memory_kb,
            MAX(COALESCE(CAST(NULLIF(MaxRSSself, '') AS BIGINT), 0)) as max_memory_kb
        FROM {table_name}
        WHERE ProcessName IS NOT NULL
        """)
    
    create_query = f"""
    CREATE TABLE build_performance_summary AS
    {' UNION ALL '.join(union_queries)}
    ORDER BY build_id
    """
    
    conn.execute(create_query)
    
    # Get stats
    summary = conn.execute("""
        SELECT 
            COUNT(*) as total_builds,
            SUM(total_processes) as total_processes_all_builds,
            AVG(duration_hours) as avg_build_duration_hours,
            MAX(max_cpu_time_ms) as peak_cpu_time_ms
        FROM build_performance_summary
    """).fetchone()
    
    print(f"   ✅ Created summary for {summary[0]} builds")
    print(f"   📊 Total processes across all builds: {summary[1]:,}")
    print(f"   ⏱️ Average build duration: {summary[2]:.2f} hours")
    print(f"   🔥 Peak CPU time: {summary[3]:,}ms")

def create_toolchain_performance_summary(conn: duckdb.DuckDBPyConnection, build_ids: List[str]):
    """Create toolchain performance summary table."""
    print("🔧 Creating toolchain performance summary table...")
    
    # Drop table if exists
    conn.execute("DROP TABLE IF EXISTS toolchain_performance_summary")
    
    union_queries = []
    for build_id in build_ids:
        table_name = f"sqlite_build_{build_id}_intercepted_process"
        
        union_queries.append(f"""
        SELECT 
            '{build_id}' as build_id,
            ProcessName as tool_name,
            COUNT(*) as usage_count,
            COUNT(DISTINCT CWD) as unique_locations,
            AVG(COALESCE(CAST(NULLIF("End", '') AS BIGINT), 0) - COALESCE(CAST(NULLIF(Start, '') AS BIGINT), 0)) as avg_duration_ms,
            SUM(COALESCE(CAST(NULLIF(CPUtime, '') AS BIGINT), 0)) as total_cpu_time_ms,
            AVG(COALESCE(CAST(NULLIF(CPUtime, '') AS BIGINT), 0)) as avg_cpu_time_ms,
            MAX(COALESCE(CAST(NULLIF(CPUtime, '') AS BIGINT), 0)) as max_cpu_time_ms,
            MAX(COALESCE(CAST(NULLIF(MaxRSSself, '') AS BIGINT), 0)) as max_memory_kb,
            CASE 
                WHEN ProcessName LIKE '%gcc%' OR ProcessName LIKE '%clang%' OR ProcessName LIKE '%g++%' THEN 'COMPILER'
                WHEN ProcessName LIKE '%make%' OR ProcessName LIKE '%ninja%' OR ProcessName LIKE '%cmake%' THEN 'BUILD_SYSTEM'
                WHEN ProcessName LIKE '%ld%' OR ProcessName LIKE '%ar%' OR ProcessName LIKE '%strip%' THEN 'LINKER'
                WHEN ProcessName LIKE '%ccache%' THEN 'CACHE'
                ELSE 'OTHER'
            END as tool_category
        FROM {table_name}
        WHERE ProcessName IS NOT NULL
        AND (ProcessName LIKE '%gcc%' OR ProcessName LIKE '%clang%' OR 
             ProcessName LIKE '%g++%' OR ProcessName LIKE '%ld%' OR
             ProcessName LIKE '%ar%' OR ProcessName LIKE '%make%' OR
             ProcessName LIKE '%cmake%' OR ProcessName LIKE '%ninja%' OR
             ProcessName LIKE '%strip%' OR ProcessName LIKE '%ranlib%' OR
             ProcessName LIKE '%ccache%')
        GROUP BY build_id, ProcessName
        """)
    
    create_query = f"""
    CREATE TABLE toolchain_performance_summary AS
    {' UNION ALL '.join(union_queries)}
    ORDER BY total_cpu_time_ms DESC
    """
    
    conn.execute(create_query)
    
    # Get stats
    summary = conn.execute("""
        SELECT 
            COUNT(*) as total_tool_entries,
            COUNT(DISTINCT tool_name) as unique_tools,
            SUM(total_cpu_time_ms) as total_toolchain_cpu_ms,
            MAX(max_cpu_time_ms) as peak_tool_cpu_ms
        FROM toolchain_performance_summary
    """).fetchone()
    
    print(f"   ✅ Created summary for {summary[1]} unique tools")
    print(f"   📊 Total tool entries: {summary[0]:,}")
    print(f"   🔥 Total toolchain CPU time: {summary[2]:,}ms")
    print(f"   ⚡ Peak tool CPU time: {summary[3]:,}ms")

def create_all_aggregated_tables(db_path: str):
    """Create all performance and security aggregated tables."""
    print("🚀 Creating Performance & Security Aggregated Tables")
    print("=" * 60)
    
    try:
        # Connect to database
        conn = duckdb.connect(db_path)
        print(f"📂 Connected to database: {db_path}")
        
        # Get available builds
        build_ids = get_available_builds(conn)
        print(f"🔍 Found builds: {', '.join(build_ids)}")
        
        if not build_ids:
            print("❌ No builds found in database")
            return False
        
        # Create all aggregated tables
        create_cpu_spike_analysis(conn, build_ids)
        create_suspicious_arguments_table(conn, build_ids)
        create_build_performance_summary(conn, build_ids)
        create_toolchain_performance_summary(conn, build_ids)
        
        # Verify tables were created
        print("\n📋 Verifying created tables...")
        tables = conn.execute("SHOW TABLES").fetchall()
        aggregated_tables = [t[0] for t in tables if t[0] in [
            'cpu_spike_analysis', 
            'suspicious_arguments', 
            'build_performance_summary',
            'toolchain_performance_summary'
        ]]
        
        for table in aggregated_tables:
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"   ✅ {table}: {count:,} rows")
        
        conn.close()
        
        print("\n🎉 All aggregated tables created successfully!")
        print("\n📝 Next steps:")
        print("1. Update your Streamlit app to query these smaller tables")
        print("2. Enjoy blazing fast performance with complete data insights")
        print("3. Add CPU spike and suspicious argument analysis to your UI")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating aggregated tables: {e}")
        return False

def main():
    """Main function."""
    # MotherDuck configuration (same as security app)
    motherduck_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRhbC5rYXB0c2FuQGluY3JlZGlidWlsZC5jb20iLCJzZXNzaW9uIjoidGFsLmthcHRzYW4uaW5jcmVkaWJ1aWxkLmNvbSIsInBhdCI6IjhPSDVYRWw2NHpQWEVzRGJpam44MUNmbE13S0xjb0U5VWxwMEx6Tnc2WVUiLCJ1c2VySWQiOiIyYjg4ZTc0Ny1kYTg1LTQwZjEtODUwNS04MmY3ZTUxZjU4MDAiLCJpc3MiOiJtZF9wYXQiLCJyZWFkT25seSI6ZmFsc2UsInRva2VuVHlwZSI6InJlYWRfd3JpdGUiLCJpYXQiOjE3NTYwNDQzMzN9.jM60vZEBOFligSptbzwV9KQCIgPdcEolHu60WTHHiX0"
    database_name = "build_analytics"
    db_path = f"md:{database_name}?motherduck_token={motherduck_token}"
    
    print("🌐 Connecting to MotherDuck cloud database...")
    
    # Create aggregated tables
    success = create_all_aggregated_tables(db_path)
    
    if success:
        print("\n🚀 Ready to update your Streamlit app for lightning-fast performance!")
        sys.exit(0)
    else:
        print("\n❌ Failed to create aggregated tables")
        sys.exit(1)

if __name__ == "__main__":
    main()
