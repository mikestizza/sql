#!/bin/bash
# Robust Cluster-Wide SQL Disk Mapper for Nutanix
# Maps SQL files to vDisks across all CVMs in a cluster

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[94m'
NC='\033[0m' # No Color
BOLD='\033[1m'

echo -e "${BOLD}==== Nutanix SQL Disk Mapper (Cluster-wide) ====${NC}"
echo -e "This script maps SQL files to Nutanix vDisks across all CVMs in the cluster"

# Prompt for Windows disk info instead of reading from a file
echo -e "\n${YELLOW}Please paste your SQL DATABASE FILES information below${NC}"
echo -e "${YELLOW}After pasting, type '${BOLD}DONE${NC}${YELLOW}' on a new line and press Enter:${NC}"
echo -e "${YELLOW}----------------------------------------${NC}"

# Create a temporary file to store user input
TMP_DISK_INFO="/tmp/windows_disk_info_temp.txt"
> $TMP_DISK_INFO  # Clear the file if it exists

# Read user input line by line until DONE is encountered
while IFS= read -r line; do
    if [ "$line" = "DONE" ]; then
        break
    fi
    echo "$line" >> $TMP_DISK_INFO
done

# Check if input is empty
if [ ! -s "$TMP_DISK_INFO" ]; then
    echo -e "\n${RED}No input provided. Exiting.${NC}"
    rm $TMP_DISK_INFO
    exit 1
fi

echo -e "\n${GREEN}Input received successfully!${NC}"

# Collect cluster info
echo -e "\n${GREEN}Collecting cluster information...${NC}"
CLUSTER_NAME=$(ncli cluster info | grep "Cluster Name" | awk -F": " '{print $2}')
echo -e "Cluster Name: ${BOLD}$CLUSTER_NAME${NC}"

# Get list of CVM IPs in the cluster more reliably
echo -e "\n${GREEN}Identifying all CVMs in the cluster...${NC}"
# Try multiple methods to get CVM IPs
CVM_IPS=$(svmips 2>/dev/null)
if [ -z "$CVM_IPS" ]; then
    echo -e "${YELLOW}svmips command failed, trying alternative methods...${NC}"
    CVM_IPS=$(ncli host list | grep "Controller VM Address" | awk '{print $4}')
fi

if [ -z "$CVM_IPS" ]; then
    echo -e "${YELLOW}Could not get CVM IPs automatically. Using local CVM only.${NC}"
    CVM_IPS=$(hostname -I | awk '{print $1}')
fi

echo -e "Found CVMs: ${BOLD}$CVM_IPS${NC}"

# Create debugging directory
DEBUG_DIR="/tmp/sql_mapper_debug"
mkdir -p $DEBUG_DIR
echo -e "Debug output will be saved to $DEBUG_DIR"

# Clear previous file if it exists
> /tmp/all_vdisks.txt

echo -e "\n${GREEN}Collecting hosted vDisks information from ALL CVMs in the cluster...${NC}"

# Try multiple methods to collect vDisk info from each CVM
for ip in $CVM_IPS; do
    echo -e "Collecting data from CVM: ${ip}"
    echo "================== $ip ==================" >> /tmp/all_vdisks.txt
    
    # Method 1: Using links to dump the hosted_vdisks page
    ssh nutanix@$ip "links --dump http:0:2009/hosted_vdisks" > "$DEBUG_DIR/vdisks_$ip.txt" 2>"$DEBUG_DIR/error_$ip.log"
    if [ $? -eq 0 ] && [ -s "$DEBUG_DIR/vdisks_$ip.txt" ]; then
        cat "$DEBUG_DIR/vdisks_$ip.txt" >> /tmp/all_vdisks.txt
        echo -e "${GREEN}Successfully collected vDisks using method 1${NC}"
    else
        echo -e "${YELLOW}Method 1 failed, trying method 2...${NC}"
        
        # Method 2: Using curl to get the data
        ssh nutanix@$ip "curl -s http://0:2009/hosted_vdisks" > "$DEBUG_DIR/vdisks_curl_$ip.txt" 2>>"$DEBUG_DIR/error_$ip.log"
        if [ $? -eq 0 ] && [ -s "$DEBUG_DIR/vdisks_curl_$ip.txt" ]; then
            cat "$DEBUG_DIR/vdisks_curl_$ip.txt" >> /tmp/all_vdisks.txt
            echo -e "${GREEN}Successfully collected vDisks using method 2${NC}"
        else
            echo -e "${YELLOW}Method 2 failed, trying method 3...${NC}"
            
            # Method 3: Direct API call for vDisks
            ssh nutanix@$ip "curl -s http://0:2009/api/vdisks/" > "$DEBUG_DIR/vdisks_api_$ip.txt" 2>>"$DEBUG_DIR/error_$ip.log"
            if [ $? -eq 0 ] && [ -s "$DEBUG_DIR/vdisks_api_$ip.txt" ]; then
                echo "API DATA FOLLOWS:" >> /tmp/all_vdisks.txt
                cat "$DEBUG_DIR/vdisks_api_$ip.txt" >> /tmp/all_vdisks.txt
                echo -e "${GREEN}Successfully collected vDisks using method 3${NC}"
            else
                echo -e "${RED}All methods failed for CVM $ip. See error logs in $DEBUG_DIR${NC}"
                echo "COLLECTION FAILED FOR THIS CVM" >> /tmp/all_vdisks.txt
            fi
        fi
    fi
done

echo -e "Cluster-wide vDisks info saved to /tmp/all_vdisks.txt"

# Create the robust mapper script
echo -e "\n${GREEN}Creating reliable cluster-wide mapper script...${NC}"

cat << 'EOF' > /tmp/cluster_mapper.py
#!/usr/bin/env python3
"""
Robust Cluster-Wide SQL Disk Mapper for Nutanix
Maps SQL files to vDisks across all CVMs in a cluster.
"""
import re
import json
import datetime
import sys
import os
import glob
import pickle

# ANSI colors for output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
BOLD = '\033[1m'
END = '\033[0m'

DEBUG_DIR = "/tmp/sql_mapper_debug"
os.makedirs(DEBUG_DIR, exist_ok=True)

def print_header(text):
    """Print a formatted header"""
    print(f"\n{BOLD}{BLUE}{'=' * 80}{END}")
    print(f"{BOLD}{BLUE}{text.center(80)}{END}")
    print(f"{BOLD}{BLUE}{'=' * 80}{END}")

def extract_sql_files(disk_info_path):
    """Extract SQL files from the Windows disk info"""
    print(f"\n{BOLD}{YELLOW}Extracting SQL Server file information{END}")
    print(f"{YELLOW}{'-' * 80}{END}")
    
    try:
        with open(disk_info_path, 'r') as f:
            content = f.read()
    except Exception as e:
        print(f"{RED}Error reading Windows disk info: {e}{END}")
        return None, None
    
    # Extract each database entry
    db_files = []
    db_pattern = re.compile(r'DATABASE: ([^\n]+)\n\s+File: ([^\n]+)(?:\n\s+Mapping Method:[^\n]+)?\n\s+Disk Number:[ ]?(\d*)\n\s+Disk Serial: ([^\n]+)\n\s+Disk UniqueId: ([^\n]+)', re.DOTALL)
    
    for match in db_pattern.finditer(content):
        db_name = match.group(1).strip()
        file_path = match.group(2).strip()
        disk_number = match.group(3).strip() if match.group(3) else None
        disk_serial = match.group(4).strip()
        disk_unique_id = match.group(5).strip()
        
        # Determine file type from extension
        file_type = "UNKNOWN"
        if file_path.lower().endswith('.mdf'):
            file_type = "PRIMARY"
        elif file_path.lower().endswith('.ndf'):
            file_type = "SECONDARY"
        elif file_path.lower().endswith('.ldf'):
            file_type = "LOG"
        elif "log" in file_path.lower():
            file_type = "LOG"
        
        file_info = {
            'database': db_name,
            'path': file_path,
            'type': file_type,
            'disk_number': disk_number,
            'disk_serial': disk_serial,
            'disk_unique_id': disk_unique_id
        }
        
        db_files.append(file_info)
    
    # Group files by disk
    disks = {}
    for file in db_files:
        disk_number = file.get('disk_number')
        if disk_number:
            if disk_number not in disks:
                disks[disk_number] = {
                    'disk_number': disk_number,
                    'serial': file.get('disk_serial'),
                    'unique_id': file.get('disk_unique_id'),
                    'files': []
                }
            disks[disk_number]['files'].append(file)
    
    print(f"{GREEN}Found {len(db_files)} SQL files on {len(disks)} disks{END}")
    
    # Save for debugging
    with open(f"{DEBUG_DIR}/sql_files.json", 'w') as f:
        json.dump(db_files, f, indent=2)
    
    return disks, db_files

def extract_vdisks_from_all_cvms():
    """Extract vDisks from all CVMs in the cluster"""
    print(f"\n{BOLD}{YELLOW}Extracting Nutanix vDisk information from ALL CVMs{END}")
    print(f"{YELLOW}{'-' * 80}{END}")
    
    # Read the combined vDisks file
    try:
        with open('/tmp/all_vdisks.txt', 'r') as f:
            content = f.read()
    except Exception as e:
        print(f"{RED}Error reading cluster-wide vDisks info: {e}{END}")
        return None, None
    
    # Split by CVM sections
    cvm_sections = re.split(r'={18} ([\d\.]+) ={18}', content)
    
    # Dictionary for lookups
    vdisks_lookup = {}
    
    # List of all vDisks found
    all_vdisks = []
    
    # Track vDisks by CVM
    vdisks_by_cvm = {}
    
    # Process each CVM's section
    for i in range(1, len(cvm_sections), 2):
        if i >= len(cvm_sections):
            break
            
        cvm_ip = cvm_sections[i]
        section_content = cvm_sections[i+1]
        
        print(f"{GREEN}Processing vDisks on CVM: {cvm_ip}{END}")
        
        # Check if we have API data
        if "API DATA FOLLOWS:" in section_content:
            # Process API JSON data
            try:
                json_start = section_content.find('{')
                if json_start >= 0:
                    json_data = section_content[json_start:]
                    data = json.loads(json_data)
                    
                    if "entities" in data:
                        for entity in data["entities"]:
                            vdisk_id = str(entity.get("vdisk_id"))
                            uuid = entity.get("vdisk_uuid", "").strip('"')
                            nfs_info = entity.get("nfs_file_location", {})
                            
                            if nfs_info:
                                vol = nfs_info.get("volume", "")
                                container = nfs_info.get("container", "")
                                objid = nfs_info.get("file_id", "")
                                
                                nfs_address = f"NFS:{vol}:{container}:{objid}"
                                nfs_address_underscore = f"NFS_{vol}_{container}_{objid}"
                                
                                vdisk = {
                                    'vdisk_id': vdisk_id,
                                    'uuid': uuid,
                                    'nfs_address': nfs_address,
                                    'nfs_address_underscore': nfs_address_underscore,
                                    'host_cvm': cvm_ip
                                }
                                
                                # Add to lookups
                                vdisks_lookup[vdisk_id] = vdisk
                                vdisks_lookup[uuid] = vdisk
                                vdisks_lookup[nfs_address] = vdisk
                                vdisks_lookup[nfs_address_underscore] = vdisk
                                
                                all_vdisks.append(vdisk)
                                
                                # Add to CVM tracking
                                if cvm_ip not in vdisks_by_cvm:
                                    vdisks_by_cvm[cvm_ip] = []
                                vdisks_by_cvm[cvm_ip].append(vdisk)
                    
                    print(f"  Found {len(vdisks_by_cvm.get(cvm_ip, []))} vDisks on CVM {cvm_ip}")
            except Exception as e:
                print(f"{RED}Error parsing API data from CVM {cvm_ip}: {e}{END}")
                with open(f"{DEBUG_DIR}/api_error_{cvm_ip}.txt", 'w') as f:
                    f.write(section_content)
        else:
            # Process regular hosted_vdisks output
            cvm_vdisks = []
            
            # Split content into lines
            lines = section_content.split('\n')
            
            # Process line by line to extract vDisks
            i = 0
            while i < len(lines) - 1:  # Need at least 2 lines for vdisk & uuid
                line = lines[i]
                
                # Look for vDisk ID pattern
                vdisk_match = re.search(r'\[\d+\](\d+)\s*\|', line)
                # Look for NFS pattern
                nfs_match = re.search(r'NFS:(\d+):(\d+):(\d+)', line)
                
                if vdisk_match and nfs_match:
                    vdisk_id = vdisk_match.group(1)
                    vol = nfs_match.group(1)
                    container = nfs_match.group(2)
                    objid = nfs_match.group(3)
                    
                    nfs_address = f"NFS:{vol}:{container}:{objid}"
                    nfs_address_underscore = f"NFS_{vol}_{container}_{objid}"
                    
                    # Try to get UUID from next line
                    uuid = None
                    if i+1 < len(lines):
                        next_line = lines[i+1]
                        uuid_match = re.search(r'\(\s*([\w-]+)\s*\)', next_line)
                        if uuid_match:
                            uuid = uuid_match.group(1)
                    
                    # Create vDisk entry
                    vdisk = {
                        'vdisk_id': vdisk_id,
                        'uuid': uuid,
                        'nfs_address': nfs_address,
                        'nfs_address_underscore': nfs_address_underscore,
                        'host_cvm': cvm_ip
                    }
                    
                    # Add to lookups
                    vdisks_lookup[vdisk_id] = vdisk
                    if uuid:
                        vdisks_lookup[uuid] = vdisk
                    vdisks_lookup[nfs_address] = vdisk
                    vdisks_lookup[nfs_address_underscore] = vdisk
                    
                    all_vdisks.append(vdisk)
                    cvm_vdisks.append(vdisk)
                    
                    # Skip next line as we've processed it for UUID
                    i += 1
                
                i += 1
            
            # Add to CVM tracking
            vdisks_by_cvm[cvm_ip] = cvm_vdisks
            print(f"  Found {len(cvm_vdisks)} vDisks on CVM {cvm_ip}")
    
    # Count unique vDisks
    unique_vdisks = set()
    for vdisk in all_vdisks:
        unique_vdisks.add(vdisk['vdisk_id'])
    
    print(f"{GREEN}Found {len(unique_vdisks)} unique vDisks across {len(vdisks_by_cvm)} CVMs in the cluster{END}")
    
    # Save debug info
    with open(f"{DEBUG_DIR}/vdisks_by_cvm.json", 'w') as f:
        json.dump({cvm: [vd['vdisk_id'] for vd in vdisks] for cvm, vdisks in vdisks_by_cvm.items()}, f, indent=2)
    
    with open(f"{DEBUG_DIR}/all_vdisks.txt", 'w') as f:
        for vdisk in all_vdisks:
            f.write(f"vDisk: {vdisk['vdisk_id']}, NFS: {vdisk['nfs_address']}, UUID: {vdisk.get('uuid', 'Unknown')}, CVM: {vdisk['host_cvm']}\n")
    
    return vdisks_lookup, all_vdisks, vdisks_by_cvm

def map_disks_to_vdisks(disks, sql_files, vdisks_lookup):
    """Map Windows disks to Nutanix vDisks"""
    print_header("Mapping SQL Files to Nutanix vDisks")
    
    # Track mappings
    mapped_disks = {}
    attempts = []
    
    for disk_number, disk in disks.items():
        serial = disk['serial']
        unique_id = disk['unique_id']
        
        vdisk_match = None
        match_method = None
        attempt_details = {
            'disk_number': disk_number,
            'serial': serial,
            'unique_id': unique_id,
            'attempts': []
        }
        
        # Try different matching strategies
        
        # 1. Try direct NFS address match
        nfs_match = re.search(r'NFS[_:](\d+)[_:](\d+)[_:](\d+)', serial)
        if nfs_match:
            vol = nfs_match.group(1)
            container = nfs_match.group(2)
            objid = nfs_match.group(3)
            
            # Try both NFS formats
            nfs_formats = [
                f"NFS:{vol}:{container}:{objid}",
                f"NFS_{vol}_{container}_{objid}"
            ]
            
            for nfs_format in nfs_formats:
                attempt_details['attempts'].append({
                    'strategy': 'NFS Path',
                    'value': nfs_format,
                    'result': nfs_format in vdisks_lookup
                })
                
                if nfs_format in vdisks_lookup:
                    vdisk_match = vdisks_lookup[nfs_format]
                    match_method = "NFS Path"
                    break
        
        # 2. Try UUID match
        if not vdisk_match:
            uuid_match = re.search(r'([\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})', serial)
            if uuid_match:
                uuid = uuid_match.group(1)
                
                attempt_details['attempts'].append({
                    'strategy': 'UUID',
                    'value': uuid,
                    'result': uuid in vdisks_lookup
                })
                
                if uuid in vdisks_lookup:
                    vdisk_match = vdisks_lookup[uuid]
                    match_method = "UUID"
        
        # 3. Try matching just the object ID
        if not vdisk_match and nfs_match:
            objid = nfs_match.group(3)
            
            # Check if any vDisk has this objid in NFS address
            for key, vdisk in vdisks_lookup.items():
                if isinstance(vdisk, dict) and 'nfs_address' in vdisk and f":{objid}" in vdisk['nfs_address']:
                    attempt_details['attempts'].append({
                        'strategy': 'NFS Object ID',
                        'value': objid,
                        'result': True
                    })
                    
                    vdisk_match = vdisk
                    match_method = "NFS Object ID"
                    break
            
            if not vdisk_match:
                attempt_details['attempts'].append({
                    'strategy': 'NFS Object ID',
                    'value': objid,
                    'result': False
                })
        
        # Store the mapping attempt
        attempts.append(attempt_details)
        
        # If we found a match, record it
        if vdisk_match:
            mapped_disks[disk_number] = {
                'disk': disk,
                'vdisk': vdisk_match,
                'match_method': match_method
            }
            
            print(f"{GREEN}Mapped Disk {disk_number} to vDisk {vdisk_match['vdisk_id']} ({vdisk_match['nfs_address']}) on CVM {vdisk_match['host_cvm']} via {match_method}{END}")
            
            # List SQL files on this disk
            for file in disk['files']:
                print(f"  - {file['path']} ({file['database']}, {file['type']})")
        else:
            print(f"{YELLOW}No vDisk match for Disk {disk_number}: {serial}{END}")
            
            # List SQL files on this unmapped disk
            for file in disk['files']:
                print(f"  - {file['path']} ({file['database']}, {file['type']})")
    
    # Save mapping attempts for debugging
    with open(f"{DEBUG_DIR}/mapping_attempts.json", 'w') as f:
        json.dump(attempts, f, indent=2)
    
    return mapped_disks

def generate_report(disks, sql_files, mapped_disks, all_vdisks, vdisks_by_cvm):
    """Generate comprehensive report of SQL files mapped to vDisks"""
    print_header("SQL Database Files to Nutanix Storage Mapping")
    
    # Group files by CVM
    files_by_cvm = {}
    unmapped_files = []
    
    for file in sql_files:
        disk_number = file.get('disk_number')
        
        if disk_number in mapped_disks:
            vdisk = mapped_disks[disk_number]['vdisk']
            cvm = vdisk['host_cvm']
            
            if cvm not in files_by_cvm:
                files_by_cvm[cvm] = []
            
            files_by_cvm[cvm].append({
                'file': file,
                'vdisk': vdisk,
                'disk_number': disk_number
            })
        else:
            unmapped_files.append(file)
    
    # Print mapped files by CVM
    for cvm, files in sorted(files_by_cvm.items()):
        print(f"\n{BOLD}{GREEN}CVM Host: {cvm}{END}")
        print("-" * 80)
        
        for entry in sorted(files, key=lambda x: (x['file']['database'], x['file']['path'])):
            file = entry['file']
            vdisk = entry['vdisk']
            disk_number = entry['disk_number']
            
            print(f"{file['database']}: {file['path']} ({file['type']})")
            print(f"  Windows Disk: {disk_number}, vDisk: {vdisk['vdisk_id']}, NFS: {vdisk['nfs_address']}")
    
    # Print unmapped files
    if unmapped_files:
        print(f"\n{BOLD}{YELLOW}Unmapped Files (Possibly Idle and Unassigned):{END}")
        print("-" * 80)
        
        for file in sorted(unmapped_files, key=lambda x: (x['database'], x['path'])):
            print(f"{file['database']}: {file['path']} ({file['type']})")
            print(f"  Windows Disk: {file.get('disk_number', 'None')}, Serial: {file.get('disk_serial', 'Unknown')}")
            print(f"  Note: This file's disk was not found on any CVM in the cluster")
    
    # Save mapping results
    result = {
        'mapped_disks': {},
        'sql_files': sql_files,
        'execution_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'cluster_details': {
            'cvms': list(vdisks_by_cvm.keys()),
            'vdisks_per_cvm': {cvm: len(vdisks) for cvm, vdisks in vdisks_by_cvm.items()}
        }
    }
    
    for disk_number, mapping in mapped_disks.items():
        result['mapped_disks'][disk_number] = {
            'disk_number': disk_number,
            'serial': mapping['disk']['serial'],
            'vdisk_id': mapping['vdisk']['vdisk_id'],
            'nfs_address': mapping['vdisk']['nfs_address'],
            'host_cvm': mapping['vdisk']['host_cvm'],
            'match_method': mapping['match_method']
        }
    
    # Save to JSON
    with open('/tmp/sql_mapping.json', 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n{GREEN}Mapping saved to /tmp/sql_mapping.json{END}")
    
    # Save CSV version
    with open('/tmp/sql_mapping.csv', 'w') as f:
        f.write('Database,File Path,File Type,Windows Disk,vDisk ID,NFS Address,Host CVM\n')
        
        for file in sql_files:
            disk_number = file.get('disk_number', '')
            vdisk_id = ''
            nfs_address = ''
            host_cvm = ''
            
            if disk_number in mapped_disks:
                vdisk = mapped_disks[disk_number]['vdisk']
                vdisk_id = vdisk['vdisk_id']
                nfs_address = vdisk['nfs_address']
                host_cvm = vdisk['host_cvm']
            
            # Clean fields for CSV
            path = file['path'].replace(',', ' ')
            
            f.write(f"{file['database']},{path},{file['type']},{disk_number},{vdisk_id},{nfs_address},{host_cvm}\n")
    
    print(f"{GREEN}CSV report saved to /tmp/sql_mapping.csv{END}")
    
    # Summary statistics
    mapped_count = sum(1 for file in sql_files if file.get('disk_number') in mapped_disks)
    
    print(f"\n{GREEN}Summary:{END}")
    print(f"- Total SQL files: {len(sql_files)}")
    print(f"- Files mapped to vDisks: {mapped_count}")
    print(f"- Files unmapped: {len(sql_files) - mapped_count}")
    print(f"- Total vDisks found: {len(all_vdisks)}")
    print(f"- Unique CVMs: {len(vdisks_by_cvm)}")
    
    print(f"\n{YELLOW}Detailed debug information available in: {DEBUG_DIR}{END}")

def main():
    """Main function"""
    print_header("Nutanix SQL Disk Mapper (Cluster-wide)")
    print(f"{BOLD}Version:{END} 5.1 (Cluster-wide with Interactive Input)")
    print(f"{BOLD}Execution Time:{END} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Get the path to the disk info file from command line argument
    disk_info_path = '/tmp/windows_disk_info_temp.txt'
    if len(sys.argv) > 1:
        disk_info_path = sys.argv[1]
    
    # Extract SQL files
    disks, sql_files = extract_sql_files(disk_info_path)
    if not disks or not sql_files:
        print(f"{RED}Failed to extract SQL files. Check input file format.{END}")
        return
    
    # Extract vDisks from all CVMs
    vdisks_lookup, all_vdisks, vdisks_by_cvm = extract_vdisks_from_all_cvms()
    if not vdisks_lookup or not all_vdisks:
        print(f"{RED}Failed to extract vDisk information from CVMs.{END}")
        return
    
    # Map disks to vDisks
    mapped_disks = map_disks_to_vdisks(disks, sql_files, vdisks_lookup)
    
    # Generate comprehensive report
    generate_report(disks, sql_files, mapped_disks, all_vdisks, vdisks_by_cvm)
    
    print(f"\n{GREEN}Mapping completed successfully!{END}")
    print(f"{GREEN}If some files remain unmapped, check the debug directory: {DEBUG_DIR}{END}")
    
    # Cleanup the temporary file
    if os.path.exists(disk_info_path) and disk_info_path == '/tmp/windows_disk_info_temp.txt':
        try:
            os.remove(disk_info_path)
            print(f"{GREEN}Temporary input file removed.{END}")
        except Exception as e:
            print(f"{YELLOW}Note: Could not remove temporary file: {e}{END}")

if __name__ == "__main__":
    main()
EOF

# Make script executable
chmod +x /tmp/cluster_mapper.py

echo -e "\n${GREEN}Setup complete!${NC}"
echo -e "${BOLD}Now running the cluster-wide mapper...${NC}\n"

# Run the mapper
cd /tmp
python3 /tmp/cluster_mapper.py

echo -e "\n${YELLOW}Mapping results have been saved to /tmp/sql_mapping.json${NC}"
echo -e "${YELLOW}CSV report has been saved to /tmp/sql_mapping.csv${NC}"
echo -e "${YELLOW}Debug information available in /tmp/sql_mapper_debug/${NC}"
echo -e "To run this tool again in the future with interactive input, simply run: ${BOLD}./sql_disk_mapper.py${NC}"
