#!/usr/bin/env python3
"""
Fast DuckDB ingest script for GM build analytics data.

This script efficiently loads raw data from:
1. SQLite databases in data/sqlite/
2. ccache log files in data/ccache/

Features:
- Fast bulk operations using DuckDB SQL
- Idempotent with replace/append modes
- Single transaction per data source
- Minimal dependencies (duckdb + stdlib only)
- No transforms - raw data "as-is"

Usage:
    python scripts/ingest_duckdb.py [--mode={replace|append}] [--output=path.duckdb]
"""

import argparse
import logging
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import List, Dict, Tuple

try:
    import duckdb
except ImportError:
    print("ERROR: duckdb not installed. Run: pip install duckdb>=1.0.0")
    sys.exit(1)


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )


def get_sqlite_files(data_dir: Path) -> List[Path]:
    """Find all SQLite database files."""
    sqlite_dir = data_dir / "sqlite"
    if not sqlite_dir.exists():
        logging.warning(f"SQLite directory not found: {sqlite_dir}")
        return []
    
    sqlite_files = list(sqlite_dir.glob("*.db"))
    logging.info(f"Found {len(sqlite_files)} SQLite files: {[f.name for f in sqlite_files]}")
    return sqlite_files


def get_ccache_files(data_dir: Path) -> List[Path]:
    """Find all ccache log files."""
    ccache_dir = data_dir / "ccache"
    if not ccache_dir.exists():
        logging.warning(f"ccache directory not found: {ccache_dir}")
        return []
    
    # Look for .txt and .log files
    log_files = list(ccache_dir.glob("*.txt")) + list(ccache_dir.glob("*.log"))
    logging.info(f"Found {len(log_files)} ccache log files: {[f.name for f in log_files]}")
    return log_files


def get_sqlite_tables(sqlite_file: Path) -> List[str]:
    """Get list of tables in a SQLite database."""
    try:
        with sqlite3.connect(sqlite_file) as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
        logging.debug(f"Tables in {sqlite_file.name}: {tables}")
        return tables
    except Exception as e:
        logging.error(f"Failed to read tables from {sqlite_file}: {e}")
        return []


def extract_build_id_from_filename(filename: str) -> str:
    """Extract build ID from filename for source tracking."""
    # Extract pattern like "24", "61", "99" from filenames
    match = re.search(r'(\d+)', filename)
    return match.group(1) if match else "unknown"


def ingest_sqlite_data(duck_conn: duckdb.DuckDBPyConnection, sqlite_files: List[Path], 
                      mode: str) -> None:
    """Ingest all SQLite databases into DuckDB using bulk operations."""
    if not sqlite_files:
        logging.info("No SQLite files to process")
        return
    
    logging.info(f"Starting SQLite ingest in {mode} mode...")
    start_time = time.time()
    
    # Install and load SQLite extension for DuckDB
    duck_conn.execute("INSTALL sqlite")
    duck_conn.execute("LOAD sqlite")
    
    # Use VARCHAR for all SQLite columns to avoid type conflicts
    duck_conn.execute("SET sqlite_all_varchar=true")
    
    total_tables = 0
    total_rows = 0
    
    for sqlite_file in sqlite_files:
        logging.info(f"Processing SQLite file: {sqlite_file.name}")
        file_start = time.time()
        
        build_id = extract_build_id_from_filename(sqlite_file.name)
        tables = get_sqlite_tables(sqlite_file)
        
        if not tables:
            logging.warning(f"No tables found in {sqlite_file.name}")
            continue
        
        # Begin transaction for this file
        duck_conn.begin()
        
        try:
            for table_name in tables:
                # Create DuckDB table name with source info
                duck_table_name = f"sqlite_{table_name}"
                
                # Drop table if replace mode
                if mode == "replace":
                    duck_conn.execute(f"DROP TABLE IF EXISTS {duck_table_name}")
                
                # Use DuckDB's SQLite extension to read table directly
                sqlite_path = str(sqlite_file.absolute())
                
                # Create table with source metadata if it doesn't exist
                if mode == "replace" or not table_exists(duck_conn, duck_table_name):
                    duck_conn.execute(f"""
                        CREATE TABLE {duck_table_name} AS 
                        SELECT 
                            '{sqlite_file.name}' as _source_file,
                            '{build_id}' as _source_build_id,
                            *
                        FROM sqlite_scan('{sqlite_path}', '{table_name}')
                    """)
                else:
                    # Append mode - insert into existing table
                    duck_conn.execute(f"""
                        INSERT INTO {duck_table_name}
                        SELECT 
                            '{sqlite_file.name}' as _source_file,
                            '{build_id}' as _source_build_id,
                            *
                        FROM sqlite_scan('{sqlite_path}', '{table_name}')
                    """)
                
                # Get row count for reporting
                result = duck_conn.execute(f"SELECT COUNT(*) FROM {duck_table_name}").fetchone()
                row_count = result[0] if result else 0
                
                logging.debug(f"  Table {table_name} -> {duck_table_name}: {row_count} total rows")
                total_rows += row_count
                total_tables += 1
            
            # Commit transaction for this file
            duck_conn.commit()
            
            file_time = time.time() - file_start
            logging.info(f"  Completed {sqlite_file.name} in {file_time:.2f}s")
            
        except Exception as e:
            duck_conn.rollback()
            logging.error(f"Failed to process {sqlite_file.name}: {e}")
            raise
    
    elapsed = time.time() - start_time
    logging.info(f"SQLite ingest completed: {total_tables} tables, {total_rows} total rows in {elapsed:.2f}s")


def table_exists(duck_conn: duckdb.DuckDBPyConnection, table_name: str) -> bool:
    """Check if table exists in DuckDB."""
    try:
        result = duck_conn.execute(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
            [table_name]
        ).fetchone()
        return result[0] > 0 if result else False
    except:
        return False


def parse_ccache_log_line(line: str) -> Tuple[str, str, str, str]:
    """Parse a ccache log line into components."""
    # Pattern: [timestamp pid] message
    # Example: [2025-07-27T09:54:28.566302 146694] === CCACHE 4.10.2-ib STARTED ===
    match = re.match(r'^\[([^\]]+)\s+(\d+)\]\s*(.*)', line.strip())
    if match:
        timestamp, pid, message = match.groups()
        return timestamp, pid, message, "parsed"
    else:
        # Return unparsed line as message
        return "", "", line.strip(), "unparsed"


def ingest_ccache_logs(duck_conn: duckdb.DuckDBPyConnection, log_files: List[Path], 
                      mode: str) -> None:
    """Ingest ccache log files into DuckDB."""
    if not log_files:
        logging.info("No ccache log files to process")
        return
    
    logging.info(f"Starting ccache log ingest in {mode} mode...")
    start_time = time.time()
    
    table_name = "ccache_logs"
    
    # Drop table if replace mode
    if mode == "replace":
        duck_conn.execute(f"DROP TABLE IF EXISTS {table_name}")
    
    # Create table if it doesn't exist
    if mode == "replace" or not table_exists(duck_conn, table_name):
        duck_conn.execute(f"""
            CREATE TABLE {table_name} (
                _source_file VARCHAR,
                _line_number BIGINT,
                timestamp VARCHAR,
                pid VARCHAR,
                message VARCHAR,
                parse_status VARCHAR,
                raw_line VARCHAR
            )
        """)
    
    total_lines = 0
    
    for log_file in log_files:
        logging.info(f"Processing ccache log: {log_file.name}")
        file_start = time.time()
        
        # Begin transaction for this file
        duck_conn.begin()
        
        try:
            # Process file in chunks for memory efficiency
            chunk_size = 10000
            chunk_data = []
            line_number = 0
            
            with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line_number += 1
                    timestamp, pid, message, parse_status = parse_ccache_log_line(line)
                    
                    chunk_data.append({
                        '_source_file': log_file.name,
                        '_line_number': line_number,
                        'timestamp': timestamp,
                        'pid': pid,
                        'message': message,
                        'parse_status': parse_status,
                        'raw_line': line.strip()
                    })
                    
                    # Insert chunk when full
                    if len(chunk_data) >= chunk_size:
                        insert_chunk(duck_conn, table_name, chunk_data)
                        total_lines += len(chunk_data)
                        chunk_data = []
                
                # Insert remaining data
                if chunk_data:
                    insert_chunk(duck_conn, table_name, chunk_data)
                    total_lines += len(chunk_data)
            
            # Commit transaction for this file
            duck_conn.commit()
            
            file_time = time.time() - file_start
            logging.info(f"  Completed {log_file.name}: {line_number} lines in {file_time:.2f}s")
            
        except Exception as e:
            duck_conn.rollback()
            logging.error(f"Failed to process {log_file.name}: {e}")
            raise
    
    elapsed = time.time() - start_time
    logging.info(f"ccache log ingest completed: {total_lines} total lines in {elapsed:.2f}s")


def insert_chunk(duck_conn: duckdb.DuckDBPyConnection, table_name: str, data: List[Dict]) -> None:
    """Insert a chunk of data efficiently using DuckDB."""
    if not data:
        return
    
    # Use DuckDB's bulk insert with executemany for efficiency
    values = []
    for row in data:
        values.append((
            row['_source_file'],
            row['_line_number'], 
            row['timestamp'],
            row['pid'],
            row['message'],
            row['parse_status'],
            row['raw_line']
        ))
    
    # Use executemany for efficient bulk insert
    duck_conn.executemany(
        f"INSERT INTO {table_name} VALUES (?, ?, ?, ?, ?, ?, ?)",
        values
    )


def main():
    parser = argparse.ArgumentParser(description="Fast DuckDB ingest for GM build analytics data")
    parser.add_argument(
        "--mode", 
        choices=["replace", "append"], 
        default="replace",
        help="Ingest mode: replace (drop existing data) or append (add to existing)"
    )
    parser.add_argument(
        "--output", 
        default="build_analytics.duckdb",
        help="Output DuckDB file path (default: build_analytics.duckdb)"
    )
    parser.add_argument(
        "--data-dir",
        default="data",
        help="Data directory containing sqlite/ and ccache/ subdirs (default: data)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    # Resolve paths
    data_dir = Path(args.data_dir)
    output_file = Path(args.output)
    
    if not data_dir.exists():
        logging.error(f"Data directory not found: {data_dir}")
        sys.exit(1)
    
    logging.info(f"Starting DuckDB ingest (mode: {args.mode})")
    logging.info(f"Data directory: {data_dir}")
    logging.info(f"Output file: {output_file}")
    
    # Connect to DuckDB
    try:
        duck_conn = duckdb.connect(str(output_file))
        
        # Enable query progress for large operations
        duck_conn.execute("PRAGMA enable_progress_bar")
        
        # Optimize for bulk loading
        duck_conn.execute("PRAGMA threads=4")
        duck_conn.execute("PRAGMA memory_limit='2GB'")
        
    except Exception as e:
        logging.error(f"Failed to connect to DuckDB: {e}")
        sys.exit(1)
    
    try:
        # Get input files
        sqlite_files = get_sqlite_files(data_dir)
        ccache_files = get_ccache_files(data_dir)
        
        total_start = time.time()
        
        # Ingest SQLite databases
        if sqlite_files:
            ingest_sqlite_data(duck_conn, sqlite_files, args.mode)
        
        # Ingest ccache logs
        if ccache_files:
            ingest_ccache_logs(duck_conn, ccache_files, args.mode)
        
        # Final statistics
        total_time = time.time() - total_start
        
        # Get table stats
        tables_result = duck_conn.execute("""
            SELECT table_name, 
                   estimated_size as row_count
            FROM duckdb_tables() 
            WHERE NOT table_name LIKE 'sqlite_%temp%'
            ORDER BY table_name
        """).fetchall()
        
        logging.info(f"\nIngest completed in {total_time:.2f}s")
        logging.info(f"Output file: {output_file} ({output_file.stat().st_size / 1024 / 1024:.1f} MB)")
        logging.info("Tables created:")
        for table_name, row_count in tables_result:
            logging.info(f"  {table_name}: {row_count:,} rows")
        
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Ingest failed: {e}")
        sys.exit(1)
    finally:
        duck_conn.close()


if __name__ == "__main__":
    main()
