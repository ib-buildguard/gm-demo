# MotherDuck Setup Guide

## 🦆 Import Your DuckDB to MotherDuck Cloud

### Step 1: Set Your MotherDuck Token
```bash
# Option A: Set as environment variable (recommended)
export MOTHERDUCK_TOKEN="your_token_here"

# Option B: Enter when prompted by the script
```

### Step 2: Run the Import Script
```bash
source .venv/bin/activate
python3 import_to_motherduck.py
```

### Step 3: Use MotherDuck in Your App
1. Start your Streamlit app
2. In the sidebar, check "Use MotherDuck Cloud"
3. Enter:
   - **MotherDuck Database**: `build_analytics` 
   - **MotherDuck Token**: Your token

## 🌟 Benefits of MotherDuck

✅ **Cloud Deployment**: Access your data from anywhere  
✅ **No Local Dependencies**: No need for local DuckDB files  
✅ **Scalability**: Handle larger datasets in the cloud  
✅ **Collaboration**: Share data with team members  
✅ **Backup**: Your data is safely stored in the cloud  

## 🔧 What the Import Script Does

1. **Connects** to your local `build_analytics.duckdb`
2. **Lists** all tables (sqlite_build_*, ccache_logs, etc.)
3. **Copies** each table to MotherDuck cloud
4. **Verifies** row counts match
5. **Provides** connection string for your app

## 📊 Expected Tables to Import

- `sqlite_build_24_intercepted_process` (~1.1M rows)
- `sqlite_build_24_process_arguments` (~146K rows)  
- `sqlite_build_24_statistics` (monitoring data)
- `sqlite_build_61_*`, `sqlite_build_62_*`, `sqlite_build_99_*` (other builds)
- `ccache_logs` (build cache logs)

## 🎯 After Import

Your security app will work exactly the same, but now:
- **Accessible from anywhere** with internet
- **No local file dependencies**
- **Ready for production deployment**
- **Shareable with team members**

## 🛠️ Troubleshooting

**Connection Issues:**
- Verify your MotherDuck token is correct
- Check internet connectivity
- Ensure DuckDB version supports MotherDuck

**Import Errors:**
- Verify local database exists: `ls -la build_analytics.duckdb`
- Check disk space for large datasets
- Try importing tables individually if needed

**App Connection:**
- Double-check database name matches what you created
- Ensure token has proper permissions
- Test connection with DuckDB CLI first
