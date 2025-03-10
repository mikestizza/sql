<#
.SYNOPSIS
  Nutanix SQL Server Disk Mapper
.DESCRIPTION
  This script retrieves SQL Server database file paths from sys.master_files and maps each file to its volume and underlying physical disk.
  It uses dynamic logic so that any database's file—regardless of name or location—can be mapped.
  
  The script gathers system info, disk info (using Get-PhysicalDisk, Get-Disk, and Win32_Volume via CIM), and outputs a report.
  Additionally, if a file is mapped to a disk, the script looks up and includes that disk's Serial Number and UniqueId.
  
.NOTES
  Run as Administrator.
  Requires the SqlServer PowerShell module (for Invoke-Sqlcmd).
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$DatabaseName = "",      # Filter for a specific database (empty = all)
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "",        # Custom output path (empty = Desktop)
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeSystemFiles = $false,  # Include system databases (master, model, msdb, tempdb, resource)
    
    [Parameter(Mandatory=$false)]
    [switch]$Detailed = $false,      # Enable extra debug output
    
    [Parameter(Mandatory=$false)]
    [int]$ScanDepth = 5              # Depth for file scanning (if fallback scanning is used)
)

# TempDB-specific functions
function Get-TempDBInfo {
    [CmdletBinding()]
    param()
    
    Write-Host "Querying for TempDB files and locations..." -ForegroundColor Cyan
    
    $tempDBFiles = @()
    
    try {
        # TempDB-specific query that bypasses the system database filter
        $query = @"
SELECT DB_NAME(database_id) AS DatabaseName,
       name AS LogicalFileName,
       type_desc AS FileType,
       physical_name AS FilePath,
       size * 8 / 1024 AS SizeMB
FROM sys.master_files
WHERE database_id = DB_ID('tempdb');
"@
        
        $connStr = "Server=localhost;Database=master;Trusted_Connection=True;TrustServerCertificate=True;"
        $results = Invoke-Sqlcmd -ConnectionString $connStr -Query $query -ErrorAction Stop
        
        if ($results -and $results.Count -gt 0) {
            Write-Host " - Found $($results.Count) TempDB files." -ForegroundColor Green
            
            foreach ($file in $results) {
                $fileObj = [PSCustomObject]@{
                    DatabaseName = 'tempdb'
                    LogicalName = $file.LogicalFileName
                    FileType = $file.FileType
                    FilePath = $file.FilePath
                    SizeMB = $file.SizeMB
                    IsTempDB = $true
                }
                
                $tempDBFiles += $fileObj
            }
        }
        else {
            Write-Host " - No TempDB files found in sys.master_files." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host " - Error querying for TempDB files: $_" -ForegroundColor Red
    }
    
    return $tempDBFiles
}

function Add-TempDBFilesToCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$TempDBFiles,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$AllInfo
    )
    
    if ($TempDBFiles.Count -gt 0) {
        Write-Host "Adding $($TempDBFiles.Count) TempDB files to collection..." -ForegroundColor Cyan
        
        foreach ($file in $TempDBFiles) {
            # Check if we already have this file in our collection
            $exists = $AllInfo.SQLInfo.DatabaseFiles | Where-Object { 
                $_.FilePath -eq $file.FilePath -and $_.DatabaseName -eq 'tempdb' 
            }
            
            if (-not $exists) {
                $AllInfo.SQLInfo.DatabaseFiles += [PSCustomObject]@{
                    DatabaseName = 'tempdb'
                    FileType = $file.FileType
                    FilePath = $file.FilePath
                    LogicalName = $file.LogicalName
                    SizeMB = $file.SizeMB
                    IsTempDB = $true
                }
                
                Write-Host " - Added TempDB file: $($file.FilePath)" -ForegroundColor Green
            }
        }
    }
}

function Map-TempDBFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AllInfo
    )
    
    Write-Host "Performing special TempDB file mapping with mountpoint detection..." -ForegroundColor Cyan
    
    # Find all tempdb files in the collection
    $tempDBDetailsToMap = $AllInfo.FileInfo.DatabaseFileDetails | Where-Object { 
        ($_.DatabaseName -eq 'tempdb' -or $_.IsTempDB -eq $true)
    }
    
    if ($tempDBDetailsToMap.Count -gt 0) {
        Write-Host " - Found $($tempDBDetailsToMap.Count) TempDB files to map." -ForegroundColor Green
        
        # Get all volumes including mountpoints for reference
        $allVolumes = Get-CimInstance -ClassName Win32_Volume -Filter "DriveType=3"
        
        foreach ($file in $tempDBDetailsToMap) {
            Write-Host "   Processing TempDB file: $($file.FilePath)" -ForegroundColor Yellow
            
            # First try to find if the file path is under a mountpoint
            $filePath = $file.FilePath
            $foundMountpoint = $false
            $mountPoint = $null
            
            # Sort volumes by path length descending to find the most specific match first
            $sortedVolumes = $allVolumes | Sort-Object { $_.Name.Length } -Descending
            
            foreach ($volume in $sortedVolumes) {
                if ($volume.Name -and -not [string]::IsNullOrEmpty($volume.Name)) {
                    $volumePath = $volume.Name.TrimEnd('\')
                    if ($filePath.StartsWith($volumePath, [StringComparison]::OrdinalIgnoreCase)) {
                        $mountPoint = $volume
                        $foundMountpoint = $true
                        Write-Host "    - Found matching mountpoint: $volumePath" -ForegroundColor Green
                        break
                    }
                }
            }
            
            if ($foundMountpoint) {
                # Try to map the mountpoint to a disk
                try {
                    # Try to find the partition using mountpoint
                    $diskNumber = $null
                    $allPartitions = Get-Partition
                    
                    foreach ($part in $allPartitions) {
                        # Check if this partition's access paths include our mountpoint
                        if ($part.AccessPaths -contains $mountPoint.Name) {
                            try {
                                $disk = Get-Disk -Number $part.DiskNumber -ErrorAction Stop
                                if ($disk) {
                                    $diskNumber = $disk.Number
                                    
                                    # Update the file mapping
                                    $file.DiskNumber = $disk.Number
                                    
                                    # Use Add-Member with check to add properties safely
                                    if (-not [bool]($file | Get-Member -Name DiskSerialNumber)) {
                                        $file | Add-Member -MemberType NoteProperty -Name DiskSerialNumber -Value $disk.SerialNumber
                                    } else {
                                        $file.DiskSerialNumber = $disk.SerialNumber
                                    }
                                    
                                    if (-not [bool]($file | Get-Member -Name DiskUniqueId)) {
                                        $file | Add-Member -MemberType NoteProperty -Name DiskUniqueId -Value $disk.UniqueId
                                    } else {
                                        $file.DiskUniqueId = $disk.UniqueId
                                    }
                                    
                                    $file.MappingMethod = "TempDB file mapped via mountpoint ($($mountPoint.Name)) to disk $($disk.Number)"
                                    Write-Host "    - Successfully mapped via mountpoint to disk $($disk.Number)" -ForegroundColor Green
                                    break
                                }
                            } catch {
                                Write-Host "    - Error getting disk for mountpoint: $_" -ForegroundColor Yellow
                            }
                        }
                    }
                    
                    # If we couldn't find it via access paths, try using volume information
                    if (-not $diskNumber) {
                        # Try alternative mapping method using Get-FileMapping function
                        $map = Get-FileMapping -FilePath $file.FilePath -Volumes $allVolumes
                        if ($map.DiskNumber) {
                            $diskInfo = $AllInfo.DiskInfo.DiskIDInfo | Where-Object { $_.Number -eq $map.DiskNumber } | Select-Object -First 1
                            if ($diskInfo) {
                                $file.DiskNumber = $diskInfo.Number
                                
                                if (-not [bool]($file | Get-Member -Name DiskSerialNumber)) {
                                    $file | Add-Member -MemberType NoteProperty -Name DiskSerialNumber -Value $diskInfo.SerialNumber
                                } else {
                                    $file.DiskSerialNumber = $diskInfo.SerialNumber
                                }
                                
                                if (-not [bool]($file | Get-Member -Name DiskUniqueId)) {
                                    $file | Add-Member -MemberType NoteProperty -Name DiskUniqueId -Value $diskInfo.UniqueId
                                } else {
                                    $file.DiskUniqueId = $diskInfo.UniqueId
                                }
                                
                                $file.MappingMethod = "TempDB file mapped via $($map.MappingMethod) to disk $($diskInfo.Number)"
                                Write-Host "    - Successfully mapped via standard mapping to disk $($diskInfo.Number)" -ForegroundColor Green
                            }
                        }
                    }
                }
                catch {
                    Write-Host "    - Error mapping via mountpoint: $_" -ForegroundColor Red
                }
            }
            
            # If mountpoint mapping failed, fall back to the original drive letter approach
            if (-not $foundMountpoint -or -not $file.DiskNumber) {
                # Get drive letter from file path
                $driveLetter = $file.FilePath.Substring(0, 1)
                
                try {
                    # Try direct mapping through partition
                    $partition = Get-Partition | Where-Object { $_.DriveLetter -eq $driveLetter } | Select-Object -First 1
                    
                    if ($partition -and $partition.DiskNumber -ne $null) {
                        try {
                            $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
                            
                            # Update the file mapping
                            $file.DiskNumber = $disk.Number
                            
                            # Use Add-Member with check to add properties safely
                            if (-not [bool]($file | Get-Member -Name DiskSerialNumber)) {
                                $file | Add-Member -MemberType NoteProperty -Name DiskSerialNumber -Value $disk.SerialNumber
                            } else {
                                $file.DiskSerialNumber = $disk.SerialNumber
                            }
                            
                            if (-not [bool]($file | Get-Member -Name DiskUniqueId)) {
                                $file | Add-Member -MemberType NoteProperty -Name DiskUniqueId -Value $disk.UniqueId
                            } else {
                                $file.DiskUniqueId = $disk.UniqueId
                            }
                            
                            $file.MappingMethod = "TempDB file on drive $($driveLetter) mapped to disk $($disk.Number)"
                            Write-Host "    - Successfully mapped to disk $($disk.Number)" -ForegroundColor Green
                        }
                        catch {
                            Write-Host "    - Error getting disk for partition: $_" -ForegroundColor Yellow
                        }
                    }
                    else {
                        # Fallback to system disk for common drive letters
                        if ($driveLetter -eq 'C') {
                            Write-Host "    - No partition found for drive C, trying system disk fallback" -ForegroundColor Yellow
                            $systemDisk = $AllInfo.DiskInfo.DiskIDInfo | Where-Object { $_.Number -eq 0 } | Select-Object -First 1
                            
                            if ($systemDisk) {
                                $file.DiskNumber = $systemDisk.Number
                                
                                if (-not [bool]($file | Get-Member -Name DiskSerialNumber)) {
                                    $file | Add-Member -MemberType NoteProperty -Name DiskSerialNumber -Value $systemDisk.SerialNumber
                                } else {
                                    $file.DiskSerialNumber = $systemDisk.SerialNumber
                                }
                                
                                if (-not [bool]($file | Get-Member -Name DiskUniqueId)) {
                                    $file | Add-Member -MemberType NoteProperty -Name DiskUniqueId -Value $systemDisk.UniqueId
                                } else {
                                    $file.DiskUniqueId = $systemDisk.UniqueId
                                }
                                
                                $file.MappingMethod = "TempDB file on system drive ($($driveLetter):) mapped to disk 0"
                                Write-Host "    - Mapped TempDB file on system drive to disk 0" -ForegroundColor Green
                            } else {
                                Write-Host "    - Could not find system disk for fallback mapping" -ForegroundColor Red
                            }
                        } else {
                            Write-Host "    - No partition found for drive $driveLetter" -ForegroundColor Yellow
                        }
                    }
                }
                catch {
                    Write-Host "    - Error mapping TempDB file: $_" -ForegroundColor Red
                }
            }
            
            # Last attempt - check if we can find similar files that might be on the same disk
            if (-not $file.DiskNumber) {
                # Try to match by folder path patterns
                $fileDirPath = [System.IO.Path]::GetDirectoryName($file.FilePath)
                $matchingFiles = $AllInfo.FileInfo.DatabaseFileDetails | Where-Object { 
                    $_.DiskNumber -and 
                    $_.FilePath -ne $file.FilePath -and 
                    $_.FilePath.StartsWith($fileDirPath.Substring(0, [Math]::Min(20, $fileDirPath.Length)))
                }
                
                if ($matchingFiles.Count -gt 0) {
                    $bestMatch = $matchingFiles | Select-Object -First 1
                    
                    $file.DiskNumber = $bestMatch.DiskNumber
                    
                    if (-not [bool]($file | Get-Member -Name DiskSerialNumber)) {
                        $file | Add-Member -MemberType NoteProperty -Name DiskSerialNumber -Value $bestMatch.DiskSerialNumber
                    } else {
                        $file.DiskSerialNumber = $bestMatch.DiskSerialNumber
                    }
                    
                    if (-not [bool]($file | Get-Member -Name DiskUniqueId)) {
                        $file | Add-Member -MemberType NoteProperty -Name DiskUniqueId -Value $bestMatch.DiskUniqueId
                    } else {
                        $file.DiskUniqueId = $bestMatch.DiskUniqueId
                    }
                    
                    $file.MappingMethod = "TempDB file mapped by path similarity to disk $($bestMatch.DiskNumber)"
                    Write-Host "    - Successfully mapped via similar path pattern to disk $($bestMatch.DiskNumber)" -ForegroundColor Green
                }
            }
        }
    }
    else {
        Write-Host " - No TempDB files found for mapping." -ForegroundColor Yellow
    }
}

function Add-TempDBReportSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AllInfo,
        
        [Parameter(Mandatory = $true)]
        [System.Text.StringBuilder]$Report
    )
    
    # Get all TempDB files
    $tempDBFiles = $AllInfo.FileInfo.DatabaseFileDetails | Where-Object { 
        $_.DatabaseName -eq 'tempdb' -or $_.IsTempDB -eq $true 
    }
    
    if ($tempDBFiles -and $tempDBFiles.Count -gt 0) {
        $Report.AppendLine("TEMPDB FILES ANALYSIS") | Out-Null
        $Report.AppendLine("----------------------------------------------") | Out-Null
        
        $Report.AppendLine("Found $($tempDBFiles.Count) TempDB files:") | Out-Null
        $Report.AppendLine("") | Out-Null
        
        # Group by actual disk number for a more accurate analysis
        $tempDbDisks = @{}
        foreach ($file in $tempDBFiles) {
            if ($file.DiskNumber -ne $null) {
                $diskKey = "Disk $($file.DiskNumber)"
                if (-not $tempDbDisks.ContainsKey($diskKey)) {
                    $tempDbDisks[$diskKey] = 0
                }
                $tempDbDisks[$diskKey]++
            } else {
                # Fallback to drive letter grouping if disk number not available
                $driveLetter = $file.FilePath.Substring(0, 3)
                if (-not $tempDbDisks.ContainsKey($driveLetter)) {
                    $tempDbDisks[$driveLetter] = 0
                }
                $tempDbDisks[$driveLetter]++
            }
        }
        
        # For the report, also track drive letter distribution to show mountpoints
        $tempDbDrives = @{}
        foreach ($file in $tempDBFiles) {
            $driveLetter = $file.FilePath.Substring(0, 3)
            if (-not $tempDbDrives.ContainsKey($driveLetter)) {
                $tempDbDrives[$driveLetter] = 0
            }
            $tempDbDrives[$driveLetter]++
        }
        
        $Report.AppendLine("TempDB File Distribution by Drive:") | Out-Null
        foreach ($drive in $tempDbDrives.Keys) {
            $Report.AppendLine("  $drive - $($tempDbDrives[$drive]) files") | Out-Null
        }
        $Report.AppendLine("") | Out-Null
        
        $Report.AppendLine("TempDB File Distribution by Physical Disk:") | Out-Null
        foreach ($disk in $tempDbDisks.Keys) {
            $Report.AppendLine("  $disk - $($tempDbDisks[$disk]) files") | Out-Null
        }
        $Report.AppendLine("") | Out-Null
        
        # Categorize by file type
        $dataFiles = $tempDBFiles | Where-Object { $_.FileType -eq "ROWS" }
        $logFiles = $tempDBFiles | Where-Object { $_.FileType -eq "LOG" }
        
        $Report.AppendLine("File Types:") | Out-Null
        $Report.AppendLine("  Data files: $($dataFiles.Count)") | Out-Null
        $Report.AppendLine("  Log files: $($logFiles.Count)") | Out-Null
        $Report.AppendLine("") | Out-Null
        
        # Best practices analysis section has been removed per request
        
        # Detailed file details section has been removed per request
        
        $Report.AppendLine("") | Out-Null
    }
}

# Set default output path if not provided
if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\NutanixSQL_Map.txt"
}

# Container for collected info
$allInfo = @{
    ComputerInfo = $null
    DiskInfo     = @{
        PhysicalDisks = $null
        DiskIDInfo    = $null
        Volumes       = $null
        PartitionInfo = $null
    }
    SQLInfo      = @{
        Instances     = $null
        DatabaseFiles = @()
    }
    FileInfo     = @{
        DatabaseFileDetails = @()
    }
    Timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

Write-Host "Starting Nutanix SQL Server Disk Mapping Tool..." -ForegroundColor Cyan

# 1. Collect system information
try {
    Write-Host "Collecting system information..." -ForegroundColor Cyan
    $allInfo.ComputerInfo = Get-ComputerInfo | Select-Object CsName, CsDomain, CsManufacturer, CsModel, OsName, OsVersion
    Write-Host " - System information collected." -ForegroundColor Green
}
catch {
    Write-Host "Error collecting system information: $_" -ForegroundColor Red
}

# 2. Gather disk information
try {
    Write-Host "Collecting disk information..." -ForegroundColor Cyan
    $allInfo.DiskInfo.PhysicalDisks = Get-PhysicalDisk | 
        Select-Object DeviceId, FriendlyName, Size, MediaType, BusType, SerialNumber, UniqueId,
                      @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}}
    $allInfo.DiskInfo.DiskIDInfo = Get-Disk | 
        Select-Object Number, FriendlyName, Size, SerialNumber, UniqueId,
                      @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}}
    # Use Get-CimInstance on Win32_Volume to get all local volumes (including mountpoints)
    $allInfo.DiskInfo.Volumes = Get-CimInstance -ClassName Win32_Volume -Filter "DriveType=3" |
        Select-Object DriveLetter, Name, Label, FileSystem, Capacity, FreeSpace,
                      @{Name="SizeGB";Expression={[math]::Round($_.Capacity/1GB,2)}}
    $allInfo.DiskInfo.PartitionInfo = Get-Partition | Where-Object { $_.DriveLetter } | 
        Select-Object DiskNumber, PartitionNumber, DriveLetter, Size,
                      @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}}
    Write-Host " - Collected info for $($allInfo.DiskInfo.PhysicalDisks.Count) physical disks and $($allInfo.DiskInfo.Volumes.Count) volumes." -ForegroundColor Green
}
catch {
    Write-Host "Error collecting disk information: $_" -ForegroundColor Red
}

# 3. Detect SQL Server instances (informational)
try {
    Write-Host "Detecting SQL Server instances..." -ForegroundColor Cyan
    $sqlInstances = @()
    $regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
    if (Test-Path $regPath) {
        $instanceProps = Get-ItemProperty "$regPath\Instance Names\SQL" -ErrorAction SilentlyContinue
        if ($instanceProps) {
            $instanceProps.PSObject.Properties | 
                Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") } |
                ForEach-Object { $sqlInstances += $_.Name }
        }
    }
    if ($sqlInstances.Count -eq 0) {
        $sqlServices = Get-Service | Where-Object { $_.Name -like "MSSQL$*" -or $_.Name -eq "MSSQLSERVER" }
        foreach ($service in $sqlServices) {
            if ($service.Name -eq "MSSQLSERVER") {
                $sqlInstances += "MSSQLSERVER"
            }
            else {
                $sqlInstances += $service.Name.Replace("MSSQL$","")
            }
        }
    }
    $allInfo.SQLInfo.Instances = $sqlInstances
    if ($sqlInstances.Count -gt 0) {
        Write-Host " - Found SQL Server instance(s): $($sqlInstances -join ', ')" -ForegroundColor Green
    }
    else {
        Write-Host " - No SQL Server instances detected; proceeding with file scanning." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Error detecting SQL Server instances: $_" -ForegroundColor Red
}

# 4. Retrieve SQL database file paths via SQL query (preferred method)
try {
    Write-Host "Querying SQL Server for database file paths..." -ForegroundColor Cyan
    $query = @"
SELECT DB_NAME(database_id) AS DatabaseName, 
       type_desc AS FileType, 
       physical_name AS FilePath
FROM sys.master_files;
"@
    # Build a connection string with Trusted_Connection and TrustServerCertificate set to True.
    $connStr = "Server=localhost;Database=master;Trusted_Connection=True;TrustServerCertificate=True;"
    $sqlFiles = Invoke-Sqlcmd -ConnectionString $connStr -Query $query -ErrorAction Stop
    Write-Host " - Retrieved $($sqlFiles.Count) file entries from SQL." -ForegroundColor Green

    $systemDatabases = @("master", "model", "msdb", "tempdb", "resource")
    foreach ($entry in $sqlFiles) {
        if (-not $IncludeSystemFiles -and ($systemDatabases -contains $entry.DatabaseName)) {
            continue
        }
        if (-not [string]::IsNullOrEmpty($DatabaseName) -and $entry.DatabaseName -ne $DatabaseName) {
            continue
        }
        $allInfo.SQLInfo.DatabaseFiles += [PSCustomObject]@{
            DatabaseName = $entry.DatabaseName
            FileType     = $entry.FileType
            FilePath     = $entry.FilePath
        }
    }
}
catch {
    Write-Host "Error querying SQL Server for file paths: $_" -ForegroundColor Yellow
    Write-Host "Falling back to file system scanning..." -ForegroundColor Yellow
    # Fallback scanning (if Invoke-Sqlcmd fails)
    $sqlFileExtensions = @("*.mdf", "*.ndf", "*.ldf")
    $drives = Get-PSDrive -PSProvider FileSystem
    foreach ($drive in $drives) {
        $drivePath = "$($drive.Name):\"
        foreach ($ext in $sqlFileExtensions) {
            $files = Get-ChildItem -Path $drivePath -Filter $ext -Recurse -File -ErrorAction SilentlyContinue -Depth $ScanDepth
            foreach ($file in $files) {
                $allInfo.SQLInfo.DatabaseFiles += [PSCustomObject]@{
                    DatabaseName = "Unknown"
                    FileType     = switch ($file.Extension.ToLower()) {
                        ".mdf" { "ROWS" }
                        ".ndf" { "ROWS" }
                        ".ldf" { "LOG" }
                        default { "UNKNOWN" }
                    }
                    FilePath     = $file.FullName
                }
            }
        }
    }
}

# Get TempDB files and add them to our collection
$tempDBFiles = Get-TempDBInfo
Add-TempDBFilesToCollection -TempDBFiles $tempDBFiles -AllInfo $allInfo

# 5. Dynamic mapping function: Get mapping details for a given file
function Get-FileMapping {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [array]$Volumes
    )
    
    $normalizedPath = $FilePath.ToLower()
    $volMatch = $null
    foreach ($vol in $Volumes) {
        if ($vol.DriveLetter) {
            $volPath = "$($vol.DriveLetter):\"
        }
        elseif (-not [string]::IsNullOrEmpty($vol.Name)) {
            $volPath = $vol.Name.TrimEnd("\")
        }
        else {
            $volPath = $FilePath.Substring(0,3)
        }
        if ($normalizedPath.StartsWith($volPath.ToLower())) {
            $volMatch = $vol
            break
        }
    }
    
    $diskNumber = $null
    $mappingMethod = ""
    if ($volMatch) {
        if ($volMatch.DriveLetter) {
            try {
                $part = Get-Partition -DriveLetter $volMatch.DriveLetter -ErrorAction Stop
                $disk = $part | Get-Disk -ErrorAction Stop
                $diskNumber = $disk.Number
                $mappingMethod = "Mapped via drive letter ($($volMatch.DriveLetter):)"
            }
            catch {
                $mappingMethod = "Error mapping via drive letter: $_"
            }
        }
        else {
            $foundPartition = $false
            $allPartitions = Get-Partition -ErrorAction SilentlyContinue
            foreach ($part in $allPartitions) {
                if ($part.AccessPaths -contains $volMatch.Name) {
                    try {
                        $disk = $part | Get-Disk -ErrorAction Stop
                        $diskNumber = $disk.Number
                        $mappingMethod = "Mapped via mount point ($($volMatch.Name)) using partition AccessPaths"
                        $foundPartition = $true
                        break
                    }
                    catch {
                        $mappingMethod = "Error mapping via partition AccessPaths: $_"
                    }
                }
            }
            if (-not $foundPartition) {
                $fileDrive = $FilePath.Substring(0,3)
                $mappingMethod = "Mapped via fallback drive letter ($fileDrive)"
            }
        }
    }
    else {
        $mappingMethod = "Volume not found for this file path"
    }
    
    return [PSCustomObject]@{
        VolumePath    = if ($volMatch) {
                            if ($volMatch.DriveLetter) {
                                "$($volMatch.DriveLetter):\"
                            }
                            elseif (-not [string]::IsNullOrEmpty($volMatch.Name)) {
                                $volMatch.Name
                            }
                            else {
                                $FilePath.Substring(0,3)
                            }
                        }
                        else {
                            "[Not Found]"
                        }
        DiskNumber    = $diskNumber
        MappingMethod = $mappingMethod
    }
}

# 6. Map each database file using the dynamic function and then look up disk serial numbers
$volumesAll = Get-CimInstance -ClassName Win32_Volume -Filter "DriveType=3"
foreach ($file in $allInfo.SQLInfo.DatabaseFiles) {
    $map = Get-FileMapping -FilePath $file.FilePath -Volumes $volumesAll
    $fileMapping = [PSCustomObject]@{
        DatabaseName  = $file.DatabaseName
        FilePath      = $file.FilePath
        FileType      = $file.FileType
        VolumePath    = $map.VolumePath
        DiskNumber    = $map.DiskNumber
        MappingMethod = $map.MappingMethod
    }
    if ($map.DiskNumber) {
        $diskInfo = $allInfo.DiskInfo.DiskIDInfo | Where-Object { $_.Number -eq $map.DiskNumber } | Select-Object -First 1
        if ($diskInfo) {
            $fileMapping | Add-Member -MemberType NoteProperty -Name DiskSerialNumber -Value $diskInfo.SerialNumber -Force
            $fileMapping | Add-Member -MemberType NoteProperty -Name DiskUniqueId -Value $diskInfo.UniqueId -Force
        }
    }
    $allInfo.FileInfo.DatabaseFileDetails += $fileMapping
}

# Enhanced mapping for local drive files that weren't properly mapped
Write-Host "Performing enhanced mapping for local drive files..." -ForegroundColor Cyan

# FORCE MAPPING FOR KNOWN PROBLEMATIC PATHS
# This adds direct path-based mapping for known paths that might cause issues
$allInfo.FileInfo.DatabaseFileDetails | ForEach-Object {
    # Specifically look for the SQL log file in Program Files
    if ($_.FilePath -like "C:\Program Files\Microsoft SQL Server*" -and $_.MappingMethod -like "*Volume not found*") {
        Write-Host "Applying direct mapping fix for SQL Server program files" -ForegroundColor Cyan
        
        # For C: drive, it's almost always disk 0
        $systemDisk = $allInfo.DiskInfo.DiskIDInfo | Where-Object { $_.Number -eq 0 } | Select-Object -First 1
        if ($systemDisk) {
            # Set the disk number property
            $_.DiskNumber = $systemDisk.Number
            
            # Use Add-Member with -Force to add or update properties
            if (-not [bool]($_ | Get-Member -Name DiskSerialNumber)) {
                $_ | Add-Member -MemberType NoteProperty -Name DiskSerialNumber -Value $systemDisk.SerialNumber
            } else {
                $_.DiskSerialNumber = $systemDisk.SerialNumber
            }
            
            if (-not [bool]($_ | Get-Member -Name DiskUniqueId)) {
                $_ | Add-Member -MemberType NoteProperty -Name DiskUniqueId -Value $systemDisk.UniqueId
            } else {
                $_.DiskUniqueId = $systemDisk.UniqueId
            }
            
            $_.MappingMethod = "Direct system disk mapping (C: drive)"
            Write-Host " - Successfully mapped SQL Server log file to system disk 0" -ForegroundColor Green
        }
    }
}

# Get any files that weren't properly mapped in the first pass
$unmappedFiles = $allInfo.FileInfo.DatabaseFileDetails | Where-Object { $_.MappingMethod -like "*Volume not found*" }

if ($unmappedFiles.Count -gt 0) {
    Write-Host " - Found $($unmappedFiles.Count) files that need enhanced mapping." -ForegroundColor Yellow
    
    foreach ($file in $unmappedFiles) {
        Write-Host "   Enhancing mapping for: $($file.FilePath)" -ForegroundColor Yellow
        
        # Get drive letter from file path (e.g., "C" from "C:\path\to\file")
        $driveLetter = $file.FilePath.Substring(0, 1)
        
        try {
            # Try direct mapping through partition
            $partition = Get-Partition | Where-Object { $_.DriveLetter -eq $driveLetter } | Select-Object -First 1
            
            if ($partition) {
                $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
                
                # Update the file mapping with the newly found information
                $file.DiskNumber = $disk.Number
                
                # Use Add-Member to add properties if they don't exist
                if (-not [bool]($file | Get-Member -Name DiskSerialNumber)) {
                    $file | Add-Member -MemberType NoteProperty -Name DiskSerialNumber -Value $disk.SerialNumber
                } else {
                    $file.DiskSerialNumber = $disk.SerialNumber
                }
                
                if (-not [bool]($file | Get-Member -Name DiskUniqueId)) {
                    $file | Add-Member -MemberType NoteProperty -Name DiskUniqueId -Value $disk.UniqueId
                } else {
                    $file.DiskUniqueId = $disk.UniqueId
                }
                
                # Fixed the string to avoid colon parsing issue
                $file.MappingMethod = "Enhanced mapping via drive letter ($($driveLetter))"
                
                Write-Host "    - Successfully mapped to disk $($disk.Number)" -ForegroundColor Green
            }
            else {
                Write-Host "    - No partition found for drive $driveLetter, trying alternate methods" -ForegroundColor Yellow
                
                # Try an alternative method using WMI
                try {
                    $wmiDisk = Get-WmiObject -Class Win32_LogicalDiskToPartition | 
                        Where-Object { $_.Dependent.DeviceID -eq "${driveLetter}:" }
                    
                    if ($wmiDisk) {
                        $partitionPath = $wmiDisk.Antecedent
                        # Extract disk number from partition path
                        if ($partitionPath -match 'Disk\s*#(\d+)') {
                            $diskNumber = $matches[1]
                            $disk = Get-Disk -Number $diskNumber -ErrorAction Stop
                            
                            # Update file mapping
                            $file.DiskNumber = $disk.Number
                            
                            # Use Add-Member to add properties if they don't exist
                            if (-not [bool]($file | Get-Member -Name DiskSerialNumber)) {
                                $file | Add-Member -MemberType NoteProperty -Name DiskSerialNumber -Value $disk.SerialNumber
                            } else {
                                $file.DiskSerialNumber = $disk.SerialNumber
                            }
                            
                            if (-not [bool]($file | Get-Member -Name DiskUniqueId)) {
                                $file | Add-Member -MemberType NoteProperty -Name DiskUniqueId -Value $disk.UniqueId
                            } else {
                                $file.DiskUniqueId = $disk.UniqueId
                            }
                            
                            $file.MappingMethod = "Enhanced mapping via WMI"
                            
                            Write-Host "    - Successfully mapped via WMI to disk $($disk.Number)" -ForegroundColor Green
                        }
                    }
                }
                catch {
                    Write-Host "    - WMI mapping failed: $_" -ForegroundColor Yellow
                }
            }
            
            # If still not mapped, try system disk fallback
            if ($file.MappingMethod -like "*Volume not found*") {
                # Final fallback - check if there's a system disk with this drive letter
                try {
                    $systemDisk = Get-CimInstance -ClassName Win32_LogicalDisk | 
                        Where-Object { $_.DeviceID -eq "${driveLetter}:" }
                    
                    if ($systemDisk) {
                        # For system drive (usually C:), it's typically disk 0
                        $matchingDisk = $allInfo.DiskInfo.DiskIDInfo | Where-Object { $_.Number -eq 0 } | Select-Object -First 1
                        
                        if ($matchingDisk) {
                            # Update file mapping
                            $file.DiskNumber = $matchingDisk.Number
                            
                            # Use Add-Member to add properties if they don't exist
                            if (-not [bool]($file | Get-Member -Name DiskSerialNumber)) {
                                $file | Add-Member -MemberType NoteProperty -Name DiskSerialNumber -Value $matchingDisk.SerialNumber
                            } else {
                                $file.DiskSerialNumber = $matchingDisk.SerialNumber
                            }
                            
                            if (-not [bool]($file | Get-Member -Name DiskUniqueId)) {
                                $file | Add-Member -MemberType NoteProperty -Name DiskUniqueId -Value $matchingDisk.UniqueId
                            } else {
                                $file.DiskUniqueId = $matchingDisk.UniqueId
                            }
                            
                            $file.MappingMethod = "Enhanced mapping to system disk"
                            
                            Write-Host "    - Successfully mapped to system disk (disk 0)" -ForegroundColor Green
                        }
                    }
                }
                catch {
                    Write-Host "    - System disk fallback mapping failed: $_" -ForegroundColor Red
                }
            }
        }
        catch {
            Write-Host "    - Error during enhanced mapping: $_" -ForegroundColor Red
        }
        
        # Double check - if still not mapped, apply direct system disk mapping
        if ($file.MappingMethod -like "*Volume not found*" -and $file.FilePath.StartsWith("C:")) {
            $systemDisk = $allInfo.DiskInfo.DiskIDInfo | Where-Object { $_.Number -eq 0 } | Select-Object -First 1
            if ($systemDisk) {
                $file.DiskNumber = $systemDisk.Number
                
                # Use Add-Member to add properties if they don't exist
                if (-not [bool]($file | Get-Member -Name DiskSerialNumber)) {
                    $file | Add-Member -MemberType NoteProperty -Name DiskSerialNumber -Value $systemDisk.SerialNumber
                } else {
                    $file.DiskSerialNumber = $systemDisk.SerialNumber
                }
                
                if (-not [bool]($file | Get-Member -Name DiskUniqueId)) {
                    $file | Add-Member -MemberType NoteProperty -Name DiskUniqueId -Value $systemDisk.UniqueId
                } else {
                    $file.DiskUniqueId = $systemDisk.UniqueId
                }
                
                $file.MappingMethod = "Forced system disk mapping (C: drive)"
                Write-Host "    - Applied forced mapping to system disk" -ForegroundColor Green
            }
        }
    }
    
    # Check if any files still have Volume not found
    $stillUnmapped = $allInfo.FileInfo.DatabaseFileDetails | Where-Object { $_.MappingMethod -like "*Volume not found*" }
    if ($stillUnmapped.Count -gt 0) {
        Write-Host " - Warning: $($stillUnmapped.Count) files could not be mapped with enhanced methods." -ForegroundColor Red
    }
    else {
        Write-Host " - All files successfully mapped with enhanced methods." -ForegroundColor Green
    }
}
else {
    Write-Host " - No files requiring enhanced mapping found." -ForegroundColor Green
}

# Perform special mapping for TempDB files
Map-TempDBFiles -AllInfo $allInfo

# 7. Generate and save the report
function Format-Size($SizeInBytes) {
    if ($SizeInBytes -ge 1TB) {
        return "$([math]::Round($SizeInBytes/1TB, 2)) TB"
    }
    elseif ($SizeInBytes -ge 1GB) {
        return "$([math]::Round($SizeInBytes/1GB, 2)) GB"
    }
    else {
        return "$([math]::Round($SizeInBytes/1MB, 2)) MB"
    }
}

$report = New-Object System.Text.StringBuilder
$report.AppendLine("==============================================") | Out-Null
$report.AppendLine("      Nutanix SQL Server Disk Mapping         ") | Out-Null
$report.AppendLine("==============================================") | Out-Null
$report.AppendLine("Generated: $($allInfo.Timestamp)") | Out-Null
if (-not [string]::IsNullOrEmpty($DatabaseName)) {
    $report.AppendLine("Database Filter: $DatabaseName") | Out-Null
}
$report.AppendLine("") | Out-Null

# System Information
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
$report.AppendLine("") | Out-Null

# SQL Server Instances
if ($allInfo.SQLInfo.Instances -and $allInfo.SQLInfo.Instances.Count -gt 0) {
    $report.AppendLine("SQL SERVER INSTANCES") | Out-Null
    $report.AppendLine("----------------------------------------------") | Out-Null
    foreach ($instance in $allInfo.SQLInfo.Instances) {
        $report.AppendLine("Instance: $instance") | Out-Null
    }
    $report.AppendLine("") | Out-Null
}

# Volume to Disk Mapping (for volumes with drive letters)
$report.AppendLine("VOLUME TO DISK MAPPING") | Out-Null
$report.AppendLine("----------------------------------------------") | Out-Null
foreach ($vol in $allInfo.DiskInfo.Volumes) {
    if ($vol.DriveLetter) {
        try {
            # Fix the colon issue by properly handling the drive letter
            $driveLetter = $vol.DriveLetter.TrimEnd(':')
            if ($driveLetter -ne '') {
                $part = Get-Partition -DriveLetter $driveLetter -ErrorAction Stop
                $disk = $part | Get-Disk -ErrorAction Stop
                $report.AppendLine("Drive $($driveLetter): mapped to Disk $($disk.Number) ($(Format-Size $disk.Size))") | Out-Null
            }
        }
        catch {
            $report.AppendLine("Drive $($driveLetter): mapping error: $_") | Out-Null
        }
    }
}
$report.AppendLine("") | Out-Null

# Physical Disks
$report.AppendLine("PHYSICAL DISKS") | Out-Null
$report.AppendLine("----------------------------------------------") | Out-Null
foreach ($disk in $allInfo.DiskInfo.DiskIDInfo | Sort-Object -Property Number) {
    $report.AppendLine("Disk Number:       $($disk.Number)") | Out-Null
    $report.AppendLine("Friendly Name:     $($disk.FriendlyName)") | Out-Null
    $report.AppendLine("Size:              $(Format-Size $disk.Size)") | Out-Null
    $report.AppendLine("Serial Number:     $($disk.SerialNumber)") | Out-Null
    $report.AppendLine("UniqueId:          $($disk.UniqueId)") | Out-Null
    $report.AppendLine("") | Out-Null
}

# Add TempDB Report section
Add-TempDBReportSection -AllInfo $allInfo -Report $report

# Database Files Mapping
$report.AppendLine("DATABASE FILES") | Out-Null
$report.AppendLine("----------------------------------------------") | Out-Null
foreach ($detail in $allInfo.FileInfo.DatabaseFileDetails) {
    $report.AppendLine("DATABASE: $($detail.DatabaseName)") | Out-Null
    $report.AppendLine("  File: $($detail.FilePath)") | Out-Null
    $report.AppendLine("  Mapping Method: $($detail.MappingMethod)") | Out-Null
    if ($detail.DiskNumber) {
        $report.AppendLine("  Disk Number: $($detail.DiskNumber)") | Out-Null
    }
    if ($detail.DiskSerialNumber) {
        $report.AppendLine("  Disk Serial: $($detail.DiskSerialNumber)") | Out-Null
    }
    if ($detail.DiskUniqueId) {
        $report.AppendLine("  Disk UniqueId: $($detail.DiskUniqueId)") | Out-Null
    }
    $report.AppendLine("") | Out-Null
}

# MAPPING GUIDANCE section has been removed per request

# Local Disk Pathing Analysis
$report.AppendLine("LOCAL DISK PATHING ANALYSIS") | Out-Null
$report.AppendLine("----------------------------------------------") | Out-Null

# First collect all fixed disks, ignoring network and removable drives
$localDisks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType = 3" | 
    Select-Object DeviceID, VolumeName, Size, FreeSpace,
                  @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},
                  @{Name="FreeGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}},
                  @{Name="PercentFree";Expression={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}}

# Get detailed filesystem path information for each disk
foreach ($disk in $localDisks) {
    $report.AppendLine("Drive: $($disk.DeviceID)") | Out-Null
    if ($disk.VolumeName) {
        $report.AppendLine("  Volume Name: $($disk.VolumeName)") | Out-Null
    }
    $report.AppendLine("  Size: $(Format-Size $disk.Size) ($($disk.SizeGB) GB)") | Out-Null
    $report.AppendLine("  Free: $(Format-Size $disk.FreeSpace) ($($disk.FreeGB) GB, $($disk.PercentFree)%)") | Out-Null
    
    # Get physical disk association
    try {
        $volumePath = "$($disk.DeviceID)\"
        $partition = Get-Partition | Where-Object { $_.DriveLetter -eq $disk.DeviceID.TrimEnd(':') } | Select-Object -First 1
        if ($partition) {
            $physicalDisk = Get-Disk -Number $partition.DiskNumber | Select-Object -First 1
            $report.AppendLine("  Physical Disk: $($physicalDisk.Number)") | Out-Null
            
            # Check if any SQL database files are on this drive
            $sqlFilesOnDrive = $allInfo.FileInfo.DatabaseFileDetails | Where-Object { $_.FilePath.StartsWith($volumePath) }
            if ($sqlFilesOnDrive.Count -gt 0) {
                $report.AppendLine("  SQL Database Files on this drive:") | Out-Null
                foreach ($sqlFile in $sqlFilesOnDrive) {
                    $report.AppendLine("    - $($sqlFile.DatabaseName): $($sqlFile.FilePath) ($($sqlFile.FileType))") | Out-Null
                }
            }
            else {
                $report.AppendLine("  No SQL Database Files on this drive") | Out-Null
            }
            
            # Get IO stats if available
            try {
                # Fix for syntax error - properly format counter path
                $driveLetter = $disk.DeviceID.TrimEnd(':')
                $counterPath = "\LogicalDisk($driveLetter)\Disk Transfers/sec"
                $diskPerf = Get-Counter -Counter $counterPath -SampleInterval 1 -MaxSamples 1 -ErrorAction SilentlyContinue
                if ($diskPerf) {
                    $iops = $diskPerf.CounterSamples.CookedValue
                    $report.AppendLine("  Current IOPS: $([math]::Round($iops, 2))") | Out-Null
                }
            }
            catch {
                # Silently continue if performance counters are not available
            }
            
            # Path analysis - check if drive path has nested folders
            if ($sqlFilesOnDrive.Count -gt 0) {
                $distinctPaths = $sqlFilesOnDrive | ForEach-Object {
                    $path = $_.FilePath.Substring($volumePath.Length)
                    $folderCount = ($path.Split('\') | Where-Object { $_ }).Count
                    [PSCustomObject]@{
                        Path = $path
                        FolderDepth = $folderCount
                    }
                }
                
                $maxDepth = ($distinctPaths | Measure-Object -Property FolderDepth -Maximum).Maximum
                $report.AppendLine("  Maximum folder nesting depth: $maxDepth") | Out-Null
                
                # Analyze folder structure for SQL files
                if ($maxDepth -gt 12) {
                    $report.AppendLine("  Warning: Deep nesting detected (>12 folders). Consider simplifying path structure.") | Out-Null
                }
            }
        }
        else {
            $report.AppendLine("  Unable to find partition information for this drive") | Out-Null
        }
    }
    catch {
        $report.AppendLine("  Error retrieving physical disk associations: $_") | Out-Null
    }
    
    $report.AppendLine("") | Out-Null
}

# Analyze disk path distribution patterns
$report.AppendLine("DISK PATH DISTRIBUTION ANALYSIS") | Out-Null
$report.AppendLine("----------------------------------------------") | Out-Null

$pathDistribution = @{}
foreach ($file in $allInfo.FileInfo.DatabaseFileDetails) {
    $driveLetter = $file.FilePath.Substring(0,3)
    if (-not $pathDistribution.ContainsKey($driveLetter)) {
        $pathDistribution[$driveLetter] = @{
            Count = 0
            DataFiles = 0
            LogFiles = 0
            FileTypes = @{}
            Databases = @{}
        }
    }
    
    $pathDistribution[$driveLetter].Count++
    
    if ($file.FileType -like "*LOG*") {
        $pathDistribution[$driveLetter].LogFiles++
    }
    else {
        $pathDistribution[$driveLetter].DataFiles++
    }
    
    if (-not $pathDistribution[$driveLetter].FileTypes.ContainsKey($file.FileType)) {
        $pathDistribution[$driveLetter].FileTypes[$file.FileType] = 0
    }
    $pathDistribution[$driveLetter].FileTypes[$file.FileType]++
    
    if (-not $pathDistribution[$driveLetter].Databases.ContainsKey($file.DatabaseName)) {
        $pathDistribution[$driveLetter].Databases[$file.DatabaseName] = 0
    }
    $pathDistribution[$driveLetter].Databases[$file.DatabaseName]++
}

foreach ($drive in $pathDistribution.Keys) {
    $report.AppendLine("Drive $drive") | Out-Null
    $report.AppendLine("  Total Files: $($pathDistribution[$drive].Count)") | Out-Null
    $report.AppendLine("  Data Files: $($pathDistribution[$drive].DataFiles)") | Out-Null
    $report.AppendLine("  Log Files: $($pathDistribution[$drive].LogFiles)") | Out-Null
    
    $report.AppendLine("  File Types:") | Out-Null
    foreach ($fileType in $pathDistribution[$drive].FileTypes.Keys) {
        # Fix for the variable/colon parsing issue
        $report.AppendLine("    - $($fileType): $($pathDistribution[$drive].FileTypes[$fileType])") | Out-Null
    }
    
    $report.AppendLine("  Databases:") | Out-Null
    foreach ($db in $pathDistribution[$drive].Databases.Keys) {
        # Fix for the variable/colon parsing issue
        $report.AppendLine("    - $($db): $($pathDistribution[$drive].Databases[$db]) files") | Out-Null
    }
    
}

$report.AppendLine("") | Out-Null

# Local Drive File Remapping
$report.AppendLine("LOCAL DRIVE FILE REMAPPING") | Out-Null
$report.AppendLine("----------------------------------------------") | Out-Null

# Count files that have enhanced mapping methods
$enhancedMappedFiles = $allInfo.FileInfo.DatabaseFileDetails | Where-Object { 
    $_.MappingMethod -like "*Enhanced mapping*" 
}

if ($enhancedMappedFiles.Count -gt 0) {
    $report.AppendLine("Successfully remapped $($enhancedMappedFiles.Count) files:") | Out-Null
    
    foreach ($file in $enhancedMappedFiles) {
        $report.AppendLine("File: $($file.FilePath)") | Out-Null
        $report.AppendLine("  Mapping Method: $($file.MappingMethod)") | Out-Null
        $report.AppendLine("  Disk Number: $($file.DiskNumber)") | Out-Null
        if ($file.DiskSerialNumber) {
            $report.AppendLine("  Disk Serial: $($file.DiskSerialNumber)") | Out-Null
        }
        if ($file.DiskUniqueId) {
            $report.AppendLine("  Disk UniqueId: $($file.DiskUniqueId)") | Out-Null
        }
        $report.AppendLine("") | Out-Null
    }
}
else {
    $report.AppendLine("No files required enhanced mapping.") | Out-Null
}

# Check if any files are still unmapped
$stillUnmapped = $allInfo.FileInfo.DatabaseFileDetails | Where-Object { 
    $_.MappingMethod -like "*Volume not found*" 
}

if ($stillUnmapped.Count -gt 0) {
    $report.AppendLine("") | Out-Null
    $report.AppendLine("WARNING: $($stillUnmapped.Count) files could not be mapped:") | Out-Null
    
    foreach ($file in $stillUnmapped) {
        $report.AppendLine("  $($file.FilePath)") | Out-Null
    }
}

$report.AppendLine("") | Out-Null

# Save report to file
$report.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
Write-Host "Disk mapping completed." -ForegroundColor Cyan
