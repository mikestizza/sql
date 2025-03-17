# Nutanix SQL Tools

A collection of tools for managing and testing SQL Server environments on Nutanix infrastructure.

## Nutanix SQL Disk Mapper

A robust cluster-wide tool for mapping SQL database files to their underlying Nutanix vDisks across all CVMs in a cluster.

### Features

- Maps SQL database files (.mdf, .ndf, .ldf) to specific Nutanix vDisks
- Collects information from all CVMs in the cluster
- Identifies which CVM hosts each database file
- Multiple approaches to match Windows disks to Nutanix vDisks
- Generates both JSON and CSV reports
- Comprehensive debug information

## How It Works

### SQL Disk Collector & Mapper

1. Collects SQL database file information from Windows
2. Identifies all CVMs in the Nutanix cluster
3. Gathers vDisk information from each CVM using multiple methods 
4. Maps Windows disk information to vDisk IDs using:
   - NFS path matching
   - UUID matching
   - Object ID matching
5. Generates reports showing which database files are on which vDisks and CVMs

### Prerequisites

- Access to Nutanix Controller VMs (CVMs)
- Python 3.x
- SSH access between CVMs
- Links or curl utilities installed on CVMs
- Run the sql_disk_collector.ps1 script on the Windows OS 

### Usage

1. Run the collector script via powershell on your databse server
NOTE: Run as Administrator (either by login or Right-Click the script to 'Run as Administrator')

```bash
./sql_disk_file_collector.ps1
```

2. Run the script on any CVM in the cluster:

```bash
./sql_disk_mapper.sh
```

3. When prompted, paste the SQL 'DATABASE FILES' section information from Windows, then type `DONE` on a new line and press 'ENTER'.

Example input format:

```
DATABASE FILES
----------------------------------------------
DATABASE: MyDatabase
    File: C:\Data\MyDatabase.mdf
    Disk Number: 1
    Disk Serial: NFS:12345:67890:98765
    Disk UniqueId: 600-01-0123-4567

DATABASE: MyDatabase
    File: C:\Data\MyDatabase_log.ldf
    Disk Number: 2
    Disk Serial: NFS:12345:67890:54321
    Disk UniqueId: 600-01-0123-8901
```

4. The script will:
   - Collect vDisk information from all CVMs in the cluster
   - Match Windows disks to Nutanix vDisks
   - Generate reports showing which CVM hosts each database file

### Output

- `/tmp/sql_mapping.json` - Detailed mapping in JSON format
- `/tmp/sql_mapping.csv` - CSV report for easy import into spreadsheets
- `/tmp/sql_mapper_debug/` - Directory with detailed debug information

## Troubleshooting

### SQL Disk Mapper

- If some files remain unmapped, check the debug directory
- If vDisk collection fails, try running directly on the CVM hosting the vDisks
- Verify the input format matches the expected pattern

## SQL Server Data Generator Tools

Tools for generating test data in SQL Server to test performance and storage growth.

### Features

- Multiple scripts for different deployment scenarios
- PowerShell and native T-SQL options
- Configurable parameters for batch size and thread count
- Creates multiple tables for parallel testing

### SQL Server Data Generator (PowerShell)

This script launches multiple SQL Server jobs to generate test data across multiple tables.

#### Prerequisites

- Windows with PowerShell
- SQL Server access
- Permissions to create and modify database objects

#### Usage

```powershell
# Basic usage with default parameters
.\SqlDataGenerator.ps1

# Custom parameters
.\SqlDataGenerator.ps1 -server "sqlserver1" -database "TestDB" -threadsPerProc 8 -batchSize 50000 -createTables
```

#### Parameters

- `-server`: SQL Server instance (default: localhost)
- `-database`: Target database (default: StizDB)
- `-threadsPerProc`: Number of threads per procedure (default: 4)
- `-batchSize`: Rows per batch (default: 100000)
- `-createTables`: Switch to create tables and stored procedures

### SQL Server Data Generator (T-SQL)

Direct T-SQL script for creating test tables and stored procedures.

#### Usage

1. Open SQL Server Management Studio
2. Connect to your target server
3. Replace 'StizDB' with your database name (if different)
4. Execute the script

## How It Works

### Data Generator

1. Creates tables with fixed-length `CHAR(8000)` columns
2. Implements stored procedures that continuously insert random data
3. Launches multiple threads to generate load in parallel
4. Uses minimal logging and table locking for maximum performance

## Troubleshooting

### Data Generator

- For performance issues, adjust batch size or thread count
- Ensure SQL Server has adequate resources
- Check SQL Server error logs for issues

## License

This project is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
