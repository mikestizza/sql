# Windows Disk Information Collector 
# Run this script as Administrator for best results

# Output file path on desktop
$outputPath = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\SQLUserDiskInfo.txt"

# Create a container for all collected information
$allInfo = @{
    ComputerInfo = $null
    SQLInfo = @{
        DatabaseFiles = @()
    }
    DiskInfo = @{
        PhysicalDisks = $null
        Partitions = $null
        Volumes = $null
        LogicalDisks = $null
        DiskIDInfo = $null
    }
    iSCSIInfo = @{
        Initiator = $null
        Targets = $null
        Sessions = $null
        Connections = $null
    }
    StorageInfo = @{
        StoragePools = $null
        VirtualDisks = $null
    }
    FileInfo = @{
        DatabaseFileDetails = @()
    }
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

Write-Host "Starting SQL Server and Windows disk information collection..." -ForegroundColor Cyan

# 1. Get basic system information
Write-Host "Collecting system information..." -ForegroundColor Green
try {
    $allInfo.ComputerInfo = Get-ComputerInfo | Select-Object CsName, CsDomain, CsManufacturer, CsModel, OsName, OsVersion
    Write-Host "  System information collected successfully" -ForegroundColor Green
}
catch {
    Write-Host "  Error collecting system information: $_" -ForegroundColor Red
}

# 2. Alternative approach for SQL Server database files using direct filesystem scan
Write-Host "Collecting SQL Server information using filesystem approach..." -ForegroundColor Green

# Common SQL Server data paths to search - focusing on Nutanix paths based on your output
$sqlDataPaths = @(
    "C:\NTNX"  # Based on your previous output
)

# File extensions to look for
$sqlFileExtensions = @("*.mdf", "*.ndf", "*.ldf")

# System database names to exclude
$systemDatabases = @('master', 'model', 'msdb', 'tempdb', 'resource')

# Directories to exclude
$excludeDirs = @(
    "C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn\Templates",
    "C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn",
    "C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA",
    "C:\NTNX\ERA_DATABASES\TEMPDB"
)

foreach ($basePath in $sqlDataPaths) {
    if (Test-Path $basePath) {
        Write-Host "  Searching for SQL files in $basePath..." -ForegroundColor Green
        
        foreach ($ext in $sqlFileExtensions) {
            try {
                # Use -File to ensure we only get files, not directories
                $files = Get-ChildItem -Path $basePath -Filter $ext -Recurse -File -ErrorAction SilentlyContinue
                
                foreach ($file in $files) {
                    # Skip files in excluded directories
                    $skipFile = $false
                    foreach ($excludeDir in $excludeDirs) {
                        if ($file.FullName -like "$excludeDir*") {
                            $skipFile = $true
                            break
                        }
                    }
                    
                    # Skip system database files
                    foreach ($sysDb in $systemDatabases) {
                        if ($file.FullName -like "*\$sysDb*" -or 
                            $file.Name -like "$sysDb*" -or
                            $file.Name -like "*$sysDb.mdf" -or
                            $file.Name -like "*$sysDb.ndf" -or
                            $file.Name -like "*$sysDb.ldf" -or
                            $file.Name -like "*$sysDb_log.ldf") {
                            $skipFile = $true
                            break
                        }
                    }
                    
                    if ($skipFile) {
                        Write-Host "    Skipping system database file: $($file.FullName)" -ForegroundColor DarkGray
                        continue
                    }
                    
                    # Determine file type based on extension
                    $fileType = switch ($file.Extension.ToLower()) {
                        ".mdf" { "ROWS" }
                        ".ndf" { "ROWS" }
                        ".ldf" { "LOG" }
                        default { "UNKNOWN" }
                    }
                    
                    # Try to determine database name from filename or path
                    $dbName = "Unknown"
                    
                    # Pattern matching for database name extraction
                    if ($file.Name -match "^(.*?)[\._]") {
                        $dbName = $matches[1]
                    }
                    
                    # Override with more specific patterns based on your environment
                    if ($file.FullName -match "\\([^\\]+)\\DATA") {
                        $dbName = $matches[1]
                    }
                    
                    # Create file record
                    $fileRecord = [PSCustomObject]@{
                        DatabaseName = $dbName
                        FilePath = $file.FullName
                        FileType = $fileType
                        FileSizeBytes = $file.Length
                    }
                    
                    # Add to our collection
                    $allInfo.SQLInfo.DatabaseFiles += $fileRecord
                    
                    Write-Host "    Found $fileType file: $($file.FullName)" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "    Error searching for $ext files: $_" -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host "  Path $basePath does not exist, skipping" -ForegroundColor Yellow
    }
}

# 3. Collect detailed disk information
Write-Host "Collecting physical disk information..." -ForegroundColor Green
try {
    # Get physical disk information
    $physicalDisks = Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, OperationalStatus, HealthStatus, Size, BusType, Model, Manufacturer, SerialNumber, UniqueId, ObjectId
    $allInfo.DiskInfo.PhysicalDisks = $physicalDisks
    Write-Host "  Physical disk information collected successfully" -ForegroundColor Green
    
    # Get partition information
    $partitions = Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size, Type, IsActive, IsBoot, IsSystem, Offset, MbrType, GptType, Guid, AccessPaths
    $allInfo.DiskInfo.Partitions = $partitions
    Write-Host "  Partition information collected successfully" -ForegroundColor Green
    
    # Get volume information
    $volumes = Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, HealthStatus, OperationalStatus, Size, SizeRemaining, AllocationUnitSize, UniqueId
    $allInfo.DiskInfo.Volumes = $volumes
    Write-Host "  Volume information collected successfully" -ForegroundColor Green
    
    # Get logical disk information
    $logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk | Select-Object DeviceID, DriveType, ProviderName, Size, FreeSpace, VolumeName, FileSystem
    $allInfo.DiskInfo.LogicalDisks = $logicalDisks
    Write-Host "  Logical disk information collected successfully" -ForegroundColor Green
    
    # Get disk ID information (including unique identifiers)
    $diskIds = Get-Disk | Select-Object Number, FriendlyName, SerialNumber, UniqueId, Path, Location, Guid
    $allInfo.DiskInfo.DiskIDInfo = $diskIds
    Write-Host "  Disk ID information collected successfully" -ForegroundColor Green
}
catch {
    Write-Host "  Error collecting disk information: $_" -ForegroundColor Red
}

# 4. Collect iSCSI information if available (with better error handling)
Write-Host "Collecting iSCSI information..." -ForegroundColor Green
try {
    # First check if the iSCSI service is running
    $iscsiService = Get-Service -Name MSiSCSI -ErrorAction SilentlyContinue
    
    if ($iscsiService -and $iscsiService.Status -eq 'Running') {
        # Try to get initiator information with error handling
        try {
            $initiator = Get-InitiatorPort -ErrorAction Stop | Select-Object NodeAddress, InstanceName, PortAddress, ConnectionType
            $allInfo.iSCSIInfo.Initiator = $initiator
            Write-Host "  Collected iSCSI initiator information" -ForegroundColor Green
        }
        catch {
            Write-Host "  Could not access iSCSI initiator information: $_" -ForegroundColor Yellow
        }
        
        # Try to get target information with error handling
        try {
            $targets = Get-IscsiTarget -ErrorAction Stop | Select-Object NodeAddress, TargetPortalAddress, IsConnected, ConnectionState, InitiatorPortalAddress
            $allInfo.iSCSIInfo.Targets = $targets
            Write-Host "  Collected iSCSI target information" -ForegroundColor Green
        }
        catch {
            Write-Host "  Could not access iSCSI target information: $_" -ForegroundColor Yellow
        }
        
        # Try to get session information with error handling
        try {
            $sessions = Get-IscsiSession -ErrorAction Stop | Select-Object InitiatorNodeAddress, TargetNodeAddress, SessionIdentifier, ConnectionIdentifier, IsPersistent, IsDiscovered, IsConnected
            $allInfo.iSCSIInfo.Sessions = $sessions
            Write-Host "  Collected iSCSI session information" -ForegroundColor Green
        }
        catch {
            Write-Host "  Could not access iSCSI session information: $_" -ForegroundColor Yellow
        }
        
        # Try to get connection information with error handling
        try {
            $connections = Get-IscsiConnection -ErrorAction Stop | Select-Object ConnectionIdentifier, TargetNodeAddress, TargetPortalAddress, InitiatorPortalAddress, ConnectionState
            $allInfo.iSCSIInfo.Connections = $connections
            Write-Host "  Collected iSCSI connection information" -ForegroundColor Green
        }
        catch {
            Write-Host "  Could not access iSCSI connection information: $_" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  iSCSI service (MSiSCSI) is not running. No iSCSI information to collect." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  Error collecting iSCSI information: $_" -ForegroundColor Red
}

# 5. Collect Storage Spaces information if available
Write-Host "Collecting Storage Spaces information..." -ForegroundColor Green
try {
    # Get storage pool information
    $storagePools = Get-StoragePool -ErrorAction SilentlyContinue | 
                   Select-Object FriendlyName, IsPrimordial, OperationalStatus, HealthStatus, Size, AllocatedSize, UniqueId, ObjectId
    $allInfo.StorageInfo.StoragePools = $storagePools
    
    # Get virtual disk information
    $virtualDisks = Get-VirtualDisk -ErrorAction SilentlyContinue | 
                   Select-Object FriendlyName, OperationalStatus, HealthStatus, Size, FootprintOnPool, PhysicalDiskRedundancy, ResiliencySettingName, UniqueId, ObjectId
    $allInfo.StorageInfo.VirtualDisks = $virtualDisks
    
    Write-Host "  Storage Spaces information collected successfully" -ForegroundColor Green
}
catch {
    Write-Host "  Error collecting Storage Spaces information: $_" -ForegroundColor Red
}

# 6. Collect detailed file information for database files
Write-Host "Collecting database file details..." -ForegroundColor Green

# Process database files that we found through filesystem scanning
if ($allInfo.SQLInfo.DatabaseFiles.Count -gt 0) {
    foreach ($file in $allInfo.SQLInfo.DatabaseFiles) {
        try {
            $fileItem = Get-Item -Path $file.FilePath -ErrorAction Stop
            
            $fileDetails = @{
                DatabaseName = $file.DatabaseName
                FilePath = $file.FilePath
                FileType = $file.FileType
                FileSizeBytes = $file.FileSizeBytes
                FileSizeGB = [math]::Round($file.FileSizeBytes / 1GB, 2)
                ActualSizeBytes = $fileItem.Length
                ActualSizeGB = [math]::Round($fileItem.Length / 1GB, 2)
                CreationTime = $fileItem.CreationTime
                LastWriteTime = $fileItem.LastWriteTime
                LastAccessTime = $fileItem.LastAccessTime
                Attributes = $fileItem.Attributes.ToString()
                FullName = $fileItem.FullName
                BaseName = $fileItem.BaseName
                Extension = $fileItem.Extension
            }
            
            # Try to get the parent drive
            if ($fileItem.FullName -match '^([A-Z]):') {
                $driveLetter = $matches[1]
                
                # Get volume info
                $volumeInfo = $allInfo.DiskInfo.Volumes | Where-Object { $_.DriveLetter -eq $driveLetter }
                if ($volumeInfo) {
                    $fileDetails.VolumeUniqueId = $volumeInfo.UniqueId
                }
                
                # Get partition info
                $partitionInfo = $allInfo.DiskInfo.Partitions | Where-Object { $_.DriveLetter -eq $driveLetter }
                if ($partitionInfo) {
                    $fileDetails.PartitionGuid = $partitionInfo.Guid
                    $fileDetails.DiskNumber = $partitionInfo.DiskNumber
                    
                    # Get physical disk info
                    $diskIdInfo = $allInfo.DiskInfo.DiskIDInfo | Where-Object { $_.Number -eq $partitionInfo.DiskNumber }
                    if ($diskIdInfo) {
                        $fileDetails.DiskSerialNumber = $diskIdInfo.SerialNumber
                        $fileDetails.DiskUniqueId = $diskIdInfo.UniqueId
                        $fileDetails.DiskPath = $diskIdInfo.Path
                    }
                }
            }
            
            $allInfo.FileInfo.DatabaseFileDetails += $fileDetails
            Write-Host "  Collected details for $($file.FilePath)" -ForegroundColor Green
        }
        catch {
            Write-Host "  Error collecting details for $($file.FilePath): $_" -ForegroundColor Red
        }
    }
}
else {
    Write-Host "  No database files found to process" -ForegroundColor Yellow
}

# 7. Collect Windows disk management information using DISKPART
Write-Host "Collecting diskpart information..." -ForegroundColor Green
try {
    # Create temporary script file
    $diskpartScriptPath = [System.IO.Path]::GetTempFileName()
    
    # Write diskpart commands to the script file
    @"
list disk
detail disk
list volume
detail volume
list partition
"@ | Out-File -FilePath $diskpartScriptPath -Encoding ASCII
    
    # Run diskpart with the script
    $diskpartOutput = & diskpart /s $diskpartScriptPath
    
    # Store the output
    $allInfo.DiskInfo.DiskPartOutput = $diskpartOutput
    
    # Clean up
    Remove-Item -Path $diskpartScriptPath -Force -ErrorAction SilentlyContinue
    
    Write-Host "  Diskpart information collected successfully" -ForegroundColor Green
}
catch {
    Write-Host "  Error collecting diskpart information: $_" -ForegroundColor Red
}

# 8. Save all collected information to a human-friendly text file
Write-Host "Creating human-friendly text output..." -ForegroundColor Green

function FormatSize {
    param (
        [Parameter(Mandatory = $true)]
        [long]$SizeInBytes
    )
    
    if ($SizeInBytes -ge 1TB) {
        return "$([math]::Round($SizeInBytes / 1TB, 2)) TB"
    }
    elseif ($SizeInBytes -ge 1GB) {
        return "$([math]::Round($SizeInBytes / 1GB, 2)) GB"
    }
    elseif ($SizeInBytes -ge 1MB) {
        return "$([math]::Round($SizeInBytes / 1MB, 2)) MB"
    }
    elseif ($SizeInBytes -ge 1KB) {
        return "$([math]::Round($SizeInBytes / 1KB, 2)) KB"
    }
    else {
        return "$SizeInBytes Bytes"
    }
}

try {
    # Create text report
    $report = New-Object System.Text.StringBuilder
    
    # Add report header
    $report.AppendLine("==============================================") | Out-Null
    $report.AppendLine("    SQL Server User Database Disk Information ") | Out-Null
    $report.AppendLine("==============================================") | Out-Null
    $report.AppendLine("Generated: $($allInfo.Timestamp)") | Out-Null
    $report.AppendLine("") | Out-Null
    
    # Add system information
    $report.AppendLine("SYSTEM INFORMATION") | Out-Null
    $report.AppendLine("----------------------------------------------") | Out-Null
    if ($allInfo.ComputerInfo) {
        $report.AppendLine("Computer Name:     $($allInfo.ComputerInfo.CsName)") | Out-Null
        $report.AppendLine("Domain:            $($allInfo.ComputerInfo.CsDomain)") | Out-Null
        $report.AppendLine("Manufacturer:      $($allInfo.ComputerInfo.CsManufacturer)") | Out-Null
        $report.AppendLine("Model:             $($allInfo.ComputerInfo.CsModel)") | Out-Null
        $report.AppendLine("Operating System:  $($allInfo.ComputerInfo.OsName)") | Out-Null
        $report.AppendLine("OS Version:        $($allInfo.ComputerInfo.OsVersion)") | Out-Null
    }
    else {
        $report.AppendLine("No system information available") | Out-Null
    }
    $report.AppendLine("") | Out-Null
    
    # Add physical disk information
    $report.AppendLine("PHYSICAL DISKS") | Out-Null
    $report.AppendLine("----------------------------------------------") | Out-Null
    if ($allInfo.DiskInfo.PhysicalDisks) {
        foreach ($disk in $allInfo.DiskInfo.PhysicalDisks) {
            $formattedSize = FormatSize -SizeInBytes $disk.Size
            
            $report.AppendLine("Disk Number:       $($disk.DeviceId)") | Out-Null
            $report.AppendLine("Friendly Name:     $($disk.FriendlyName)") | Out-Null
            $report.AppendLine("Model:             $($disk.Model)") | Out-Null
            $report.AppendLine("Size:              $formattedSize") | Out-Null
            $report.AppendLine("Media Type:        $($disk.MediaType)") | Out-Null
            $report.AppendLine("Bus Type:          $($disk.BusType)") | Out-Null
            $report.AppendLine("Serial Number:     $($disk.SerialNumber)") | Out-Null
            $report.AppendLine("UniqueId:          $($disk.UniqueId)") | Out-Null
            $report.AppendLine("") | Out-Null
        }
    }
    else {
        $report.AppendLine("No physical disk information available") | Out-Null
        $report.AppendLine("") | Out-Null
    }
    
    # Add volume information
    $report.AppendLine("VOLUMES") | Out-Null
    $report.AppendLine("----------------------------------------------") | Out-Null
    if ($allInfo.DiskInfo.Volumes) {
        foreach ($volume in $allInfo.DiskInfo.Volumes) {
            if ($volume.DriveLetter) {
                $formattedSize = FormatSize -SizeInBytes $volume.Size
                $formattedFree = FormatSize -SizeInBytes $volume.SizeRemaining
                
                $report.AppendLine("Drive Letter:      $($volume.DriveLetter):") | Out-Null
                $report.AppendLine("Label:             $($volume.FileSystemLabel)") | Out-Null
                $report.AppendLine("File System:       $($volume.FileSystem)") | Out-Null
                $report.AppendLine("Size:              $formattedSize") | Out-Null
                $report.AppendLine("Free Space:        $formattedFree") | Out-Null
                $report.AppendLine("Health Status:     $($volume.HealthStatus)") | Out-Null
                $report.AppendLine("Unique ID:         $($volume.UniqueId)") | Out-Null
                $report.AppendLine("") | Out-Null
            }
        }
    }
    else {
        $report.AppendLine("No volume information available") | Out-Null
        $report.AppendLine("") | Out-Null
    }
    
    # Add database file information
    $report.AppendLine("USER DATABASE FILES") | Out-Null
    $report.AppendLine("----------------------------------------------") | Out-Null
    if ($allInfo.SQLInfo.DatabaseFiles.Count -gt 0) {
        # Group by database name
        $databaseGroups = $allInfo.SQLInfo.DatabaseFiles | Group-Object -Property DatabaseName
        
        foreach ($dbGroup in $databaseGroups) {
            $report.AppendLine("DATABASE: $($dbGroup.Name)") | Out-Null
            $report.AppendLine("") | Out-Null
            
            foreach ($file in $dbGroup.Group) {
                $formattedSize = FormatSize -SizeInBytes $file.FileSizeBytes
                
                $report.AppendLine("  File: $($file.FilePath)") | Out-Null
                $report.AppendLine("  Type: $($file.FileType)") | Out-Null
                $report.AppendLine("  Size: $formattedSize") | Out-Null
                
                # Get additional details from the detailed file info
                $fileDetail = $allInfo.FileInfo.DatabaseFileDetails | Where-Object { $_.FilePath -eq $file.FilePath }
                if ($fileDetail) {
                    if ($fileDetail.DiskNumber) {
                        $report.AppendLine("  Disk Number: $($fileDetail.DiskNumber)") | Out-Null
                    }
                    if ($fileDetail.DiskSerialNumber) {
                        $report.AppendLine("  Disk Serial: $($fileDetail.DiskSerialNumber)") | Out-Null
                    }
                    if ($fileDetail.DiskUniqueId) {
                        $report.AppendLine("  Disk UniqueId: $($fileDetail.DiskUniqueId)") | Out-Null
                    }
                    if ($fileDetail.VolumeUniqueId) {
                        $report.AppendLine("  Volume UniqueId: $($fileDetail.VolumeUniqueId)") | Out-Null
                    }
                }
                
                $report.AppendLine("") | Out-Null
            }
        }
    }
    else {
        $report.AppendLine("No user database files found") | Out-Null
        $report.AppendLine("") | Out-Null
    }
    
    # Add iSCSI information if available
    $report.AppendLine("iSCSI INFORMATION") | Out-Null
    $report.AppendLine("----------------------------------------------") | Out-Null
    
    if ($allInfo.iSCSIInfo.Initiator) {
        $report.AppendLine("iSCSI Initiator:") | Out-Null
        foreach ($initiator in $allInfo.iSCSIInfo.Initiator) {
            $report.AppendLine("  Node Address:   $($initiator.NodeAddress)") | Out-Null
            $report.AppendLine("  Port Address:   $($initiator.PortAddress)") | Out-Null
            $report.AppendLine("") | Out-Null
        }
    }
    
    if ($allInfo.iSCSIInfo.Targets) {
        $report.AppendLine("iSCSI Targets:") | Out-Null
        foreach ($target in $allInfo.iSCSIInfo.Targets) {
            $report.AppendLine("  Node Address:   $($target.NodeAddress)") | Out-Null
            $report.AppendLine("  Portal Address: $($target.TargetPortalAddress)") | Out-Null
            $report.AppendLine("  Connected:      $($target.IsConnected)") | Out-Null
            $report.AppendLine("") | Out-Null
        }
    }
    
    if (-not $allInfo.iSCSIInfo.Initiator -and -not $allInfo.iSCSIInfo.Targets) {
        $report.AppendLine("No iSCSI information available or iSCSI is not in use") | Out-Null
        $report.AppendLine("") | Out-Null
    }
    
    # Add DISKPART raw output
    $report.AppendLine("DISKPART OUTPUT") | Out-Null
    $report.AppendLine("----------------------------------------------") | Out-Null
    if ($allInfo.DiskInfo.DiskPartOutput) {
        $report.AppendLine($allInfo.DiskInfo.DiskPartOutput) | Out-Null
    }
    else {
        $report.AppendLine("No DISKPART information available") | Out-Null
    }
    $report.AppendLine("") | Out-Null
    
    # Add guidance for mapping to Nutanix
    $report.AppendLine("MAPPING GUIDANCE") | Out-Null
    $report.AppendLine("----------------------------------------------") | Out-Null
    $report.AppendLine("To map Windows disks to Nutanix volumes:") | Out-Null
    $report.AppendLine("") | Out-Null
    $report.AppendLine("1. Note the Disk UniqueId values above") | Out-Null
    $report.AppendLine("2. On Nutanix CVM, run 'acli vg.list' to get volume groups") | Out-Null
    $report.AppendLine("3. For each volume group, run 'acli vg.get <name>'") | Out-Null
    $report.AppendLine("4. If using iSCSI, match the target names") | Out-Null
    $report.AppendLine("5. If direct attach, match UUID patterns") | Out-Null
    $report.AppendLine("6. Look for size correlations between disks") | Out-Null
    $report.AppendLine("") | Out-Null
    
    # Save report to file
    $report.ToString() | Out-File -FilePath $outputPath -Encoding UTF8
    Write-Host "Saved human-readable report to $outputPath" -ForegroundColor Green
}
catch {
    Write-Host "Error creating text report: $_" -ForegroundColor Red
}

# 9. Display summary
Write-Host "`nSummary of collected information:" -ForegroundColor Cyan

# System info status
$systemInfoStatus = if ($null -ne $allInfo.ComputerInfo) { 'Collected' } else { 'Missing' }
Write-Host "  System information:        $systemInfoStatus" -ForegroundColor White

# Database files status
$dbFilesStatus = if ($allInfo.SQLInfo.DatabaseFiles.Count -gt 0) { 
    "$($allInfo.SQLInfo.DatabaseFiles.Count) files" 
} else { 
    'Missing' 
}
Write-Host "  User database files:       $dbFilesStatus" -ForegroundColor White

# Physical disks status
$physicalDisksStatus = if ($null -ne $allInfo.DiskInfo.PhysicalDisks) { 
    "$($allInfo.DiskInfo.PhysicalDisks.Count) disks" 
} else { 
    'Missing' 
}
Write-Host "  Physical disks:            $physicalDisksStatus" -ForegroundColor White

# Volumes status
$volumesStatus = if ($null -ne $allInfo.DiskInfo.Volumes) { 
    "$($allInfo.DiskInfo.Volumes.Count) volumes" 
} else { 
    'Missing' 
}
Write-Host "  Volumes:                   $volumesStatus" -ForegroundColor White

# iSCSI targets status
$iscsiStatus = if ($null -ne $allInfo.iSCSIInfo.Targets) { 
    "$($allInfo.iSCSIInfo.Targets.Count) targets" 
} else { 
    'Missing/Not in use' 
}
Write-Host "  iSCSI information:         $iscsiStatus" -ForegroundColor White

Write-Host "`nResults have been saved to $outputPath in a human-readable format." -ForegroundColor Green
Write-Host "Open this file to review details and follow the mapping guidance at the end of the file." -ForegroundColor White
