#!/usr/bin/env python3
"""
Import local DuckDB database to MotherDuck
This script copies all tables from your local build_analytics.duckdb to MotherDuck cloud.
"""

import duckdb
import os
import sys
from typing import List, Dict

def get_motherduck_token():
    """Get MotherDuck token from environment or user input."""
    token = os.getenv('MOTHERDUCK_TOKEN')
    if not token:
        print("MotherDuck token not found in environment variable MOTHERDUCK_TOKEN")
        token = input("Please enter your MotherDuck token: ").strip()
        if not token:
            print("Error: MotherDuck token is required")
            sys.exit(1)
    return token

def connect_to_motherduck(token: str, database_name: str = "build_analytics"):
    """Connect to MotherDuck with the provided token."""
    try:
        # First connect to the main MotherDuck instance
        print(f"🔗 Connecting to MotherDuck...")
        main_conn = duckdb.connect(f"md:?motherduck_token={token}")
        
        # Create the database if it doesn't exist
        print(f"📝 Creating database '{database_name}' if it doesn't exist...")
        main_conn.execute(f"CREATE DATABASE IF NOT EXISTS {database_name}")
        main_conn.close()
        
        # Now connect to the specific database
        connection_string = f"md:{database_name}?motherduck_token={token}"
        conn = duckdb.connect(connection_string)
        print(f"✅ Successfully connected to MotherDuck database: {database_name}")
        return conn
    except Exception as e:
        print(f"❌ Failed to connect to MotherDuck: {e}")
        print(f"💡 Make sure your token is valid and has write permissions")
        sys.exit(1)

def get_local_tables(local_db_path: str) -> List[str]:
    """Get list of all tables in the local DuckDB database."""
    try:
        local_conn = duckdb.connect(local_db_path)
        tables = local_conn.execute("SHOW TABLES").fetchall()
        table_names = [table[0] for table in tables]
        local_conn.close()
        print(f"📋 Found {len(table_names)} tables in local database")
        return table_names
    except Exception as e:
        print(f"❌ Failed to read local database: {e}")
        sys.exit(1)

def copy_table_to_motherduck(local_db_path: str, motherduck_conn, table_name: str):
    """Copy a single table from local DuckDB to MotherDuck."""
    try:
        # Attach local database to MotherDuck connection
        motherduck_conn.execute(f"ATTACH '{local_db_path}' AS local_db")
        
        # Get table info
        count_result = motherduck_conn.execute(f"SELECT COUNT(*) FROM local_db.{table_name}").fetchone()
        row_count = count_result[0] if count_result else 0
        
        print(f"📦 Copying table '{table_name}' ({row_count:,} rows)...")
        
        # Drop table if it exists in MotherDuck
        motherduck_conn.execute(f"DROP TABLE IF EXISTS {table_name}")
        
        # Copy table structure and data
        motherduck_conn.execute(f"CREATE TABLE {table_name} AS SELECT * FROM local_db.{table_name}")
        
        # Verify the copy
        copied_count = motherduck_conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
        
        if copied_count == row_count:
            print(f"✅ Successfully copied '{table_name}' ({copied_count:,} rows)")
        else:
            print(f"⚠️ Warning: Row count mismatch for '{table_name}' (expected {row_count}, got {copied_count})")
        
        # Detach local database
        motherduck_conn.execute("DETACH local_db")
        
    except Exception as e:
        print(f"❌ Failed to copy table '{table_name}': {e}")
        try:
            motherduck_conn.execute("DETACH local_db")
        except:
            pass

def main():
    print("🦆 MotherDuck Import Tool")
    print("=" * 50)
    
    # Configuration
    local_db_path = "build_analytics.duckdb"
    motherduck_database = "build_analytics"
    
    # Check if local database exists
    if not os.path.exists(local_db_path):
        print(f"❌ Local database not found: {local_db_path}")
        print("Please run the ingest script first to create the local database.")
        sys.exit(1)
    
    # Get MotherDuck token
    token = get_motherduck_token()
    
    # Connect to MotherDuck
    motherduck_conn = connect_to_motherduck(token, motherduck_database)
    
    # Get list of tables from local database
    table_names = get_local_tables(local_db_path)
    
    if not table_names:
        print("❌ No tables found in local database")
        sys.exit(1)
    
    print(f"📋 Tables to copy: {', '.join(table_names)}")
    
    # Confirm before proceeding
    response = input(f"\n🤔 Copy {len(table_names)} tables to MotherDuck database '{motherduck_database}'? (y/N): ")
    if response.lower() not in ['y', 'yes']:
        print("❌ Import cancelled by user")
        sys.exit(0)
    
    print("\n🚀 Starting import...")
    
    # Copy each table
    success_count = 0
    for table_name in table_names:
        try:
            copy_table_to_motherduck(local_db_path, motherduck_conn, table_name)
            success_count += 1
        except Exception as e:
            print(f"❌ Failed to copy '{table_name}': {e}")
    
    # Summary
    print("\n" + "=" * 50)
    print(f"🎉 Import complete!")
    print(f"✅ Successfully copied: {success_count}/{len(table_names)} tables")
    
    if success_count == len(table_names):
        print(f"🌐 Your data is now available in MotherDuck database: {motherduck_database}")
        print(f"🔗 Access it at: https://app.motherduck.com")
        
        # Show connection string for the app
        print(f"\n📝 To use in your Streamlit app, update the connection string to:")
        print(f"   md:{motherduck_database}?motherduck_token=YOUR_TOKEN")
    else:
        print("⚠️ Some tables failed to copy. Check the errors above.")
    
    motherduck_conn.close()

if __name__ == "__main__":
    main()
