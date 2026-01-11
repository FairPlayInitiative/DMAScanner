<#
.SYNOPSIS
3-Color DMA Detection Script + Optional Discord Webhook

Copyright (c) EreVeX. All rights reserved.
#>

[CmdletBinding()]
param(
    [switch]$ExportResults,
    [string]$ExportPath = "$PSScriptRoot\DMA_Scan_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

Write-Host "`n===== DMA DETECTION SCRIPT =====" -ForegroundColor Cyan

#region Configuration Variables

# Prompt for name - optional feature
try {
    $webhookName = Read-Host "Please Enter a Name (for reference use only)"
    if ($webhookName) {
        $webhookName = $webhookName.Trim()
    } else {
        $webhookName = $null
    }
} catch {
    $webhookName = $null
}

# Prompt for Discord webhook URL - optional feature
try {
    $webhookUrl = Read-Host "Enter Discord webhook URL (or press Enter to skip)"
    if ($webhookUrl) {
        # Enhanced input validation
        $webhookUrl = $webhookUrl.Trim()
        if ($webhookUrl -notmatch "^https://(discord\.com|discordapp\.com)/api/webhooks/[\w/]+$") {
            Write-Host "Invalid webhook URL format. Expected: https://discord.com/api/webhooks/..." -ForegroundColor Yellow
            $webhookUrl = $null
        }
    } else {
        $webhookUrl = $null
    }
} catch {
    $webhookUrl = $null
}

# Known suspicious vendor IDs that are commonly used in DMA devices
$Global:SuspiciousVendors = @("10EE", "04B4", "1050", "16D0", "1209", "2E8A")

# Keywords that indicate potential DMA cheat tools
$Global:SuspiciousKeywords = @(
    "PCILeech",
    "LeechCore",
    "MemProcFS",
    "MemStream",
    "Screamer",
    "Screamer PCIe",
    "PCIe Squirrel",
    "CaptainDMA",
    "LeetDMA",
    "RaptorDMA",
    "RangerDMA",
    "ZDMA",
    "Thunderclap",
    "Thunderspy",
    "Inception DMA",
    "FinFireWire",
    "FPGA",
    "PCIe DMA",
    "Thunderbolt DMA",
    "ExpressCard",
    "M.2 DMA",
    "DMA",
    "Xilinx",
    "Capture",
    "Debug Bridge",
    "KMBox",
    "Kimb",
    "Kimbox",
    "Fuser",
    "Squirrel",
    # --- Extra targeted DMA tool/hardware/project names ---
    "PCIeFeeder",
    "PCI-E Sniffer",
    "PCIe Tap",
    "PCIe SPY",
    "LPCLeech",
    "EasyDMA",
    "PCIeMiner",
    "PCIeXpressCard",
    "ICED-Technologies Board",
    "PCIeScreamer Nano",
    "PCIeGlitch",
    "PCIeSplicer",
    "RaptorDMA Nano",
    "RaptorDMA II",
    "RADcapturer",
    "Bus Pirate"
)

# These vendors are known to be safe and can be ignored
$Global:KnownSafeVendors = @("Intel", "NVIDIA", "AMD", "Realtek", "Microsoft", "Logitech", "Corsair", "Kingston", "Samsung", "ASUS", "Broadcom")

# Cache for registry path checks
$Global:RegistryPathCache = @{}

# Compiled regex patterns for performance
$Global:VendorRegex = [regex]::new("VEN_(" + ($Global:SuspiciousVendors -join "|") + ")", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$Global:DmaKeywordRegex = [regex]::new("\bDMA\b", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$Global:DmaExcludeRegex = [regex]::new("UDMA|IDE DMA|DMA Controller|DMA Channel|ATAPI DMA", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

#endregion

#region Helper Functions

# Compatibility check functions
function Test-WindowsVersion {
    # Returns Windows version info for compatibility checks
    try {
        $os = Get-CimInstanceCompat -ClassName "Win32_OperatingSystem"
        if ($os) {
            return @{
                Version = [version]$os.Version
                MajorVersion = $os.Version.Split('.')[0]
                BuildNumber = $os.BuildNumber
            }
        }
    } catch {}
    
    # Fallback if all methods fail
    return @{ Version = [version]"10.0.0"; MajorVersion = "10"; BuildNumber = "0" }
}

function Get-CimInstanceCompat {
    # Compatibility wrapper for Get-CimInstance with fallback to Get-WmiObject for older Windows
    param(
        [string]$ClassName,
        [string]$Namespace = $null,
        [string]$Filter = $null
    )
    
    # Try CIM first (Windows 8+)
    try {
        if ($Namespace) {
            if ($Filter) {
                $result = Get-CimInstance -Namespace $Namespace -ClassName $ClassName -Filter $Filter -ErrorAction SilentlyContinue
                if ($result) { return $result }
            } else {
                $result = Get-CimInstance -Namespace $Namespace -ClassName $ClassName -ErrorAction SilentlyContinue
                if ($result) { return $result }
            }
        } else {
            if ($Filter) {
                $result = Get-CimInstance -ClassName $ClassName -Filter $Filter -ErrorAction SilentlyContinue
                if ($result) { return $result }
            } else {
                $result = Get-CimInstance -ClassName $ClassName -ErrorAction SilentlyContinue
                if ($result) { return $result }
            }
        }
    } catch {
        # CIM failed, try WMI fallback
    }
    
    # Fallback to WMI for older systems (Windows 7 and earlier)
    try {
        if ($Namespace) {
            if ($Filter) {
                return Get-WmiObject -Namespace $Namespace -Class $ClassName -Filter $Filter -ErrorAction SilentlyContinue
            } else {
                return Get-WmiObject -Namespace $Namespace -Class $ClassName -ErrorAction SilentlyContinue
            }
        } else {
            if ($Filter) {
                return Get-WmiObject -Class $ClassName -Filter $Filter -ErrorAction SilentlyContinue
            } else {
                return Get-WmiObject -Class $ClassName -ErrorAction SilentlyContinue
            }
        }
    } catch {
        return $null
    }
}

function Write-ProgressStep {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
}

function Get-KernelDMAProtectionStatus {
    # Returns: $true if enabled, $false if disabled, $null if unsupported
    # Cache registry path check
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelDmaProtection"
    
    if (-not $Global:RegistryPathCache.ContainsKey($regPath)) {
        $Global:RegistryPathCache[$regPath] = Test-Path $regPath
    }
    
    # Method 1: Check registry directly (most reliable method)
    try {
        if ($Global:RegistryPathCache[$regPath]) {
            $regValue = Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue
            if ($regValue) {
                if ($regValue.Enabled -eq 1) {
                    return $true
                } elseif ($regValue.Enabled -eq 0) {
                    return $false
                }
            }
        } else {
            # Registry path doesn't exist - feature is likely unsupported
            return $null
        }
    } catch {
        Write-Warning "Error checking Kernel DMA Protection registry: $($_.Exception.Message). Try running as Administrator."
    }
    
    # Method 2: Check via WMI/CIM (DeviceGuard namespace) - Windows 10 1803+
    try {
        $dmaStatus = Get-CimInstanceCompat -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard"
        if ($dmaStatus) {
            $kdpStatus = $dmaStatus | Select-Object -ExpandProperty KernelDmaProtectionStatus -ErrorAction SilentlyContinue
            # Status values: 0=Off, 1=On, 2=On with UEFI lock
            if ($kdpStatus -eq 1 -or $kdpStatus -eq 2) {
                return $true
            } elseif ($kdpStatus -eq 0) {
                return $false
            }
        }
    } catch {
        # DeviceGuard namespace may not exist on older Windows versions - this is expected
    }
    
    # Method 3: Check System Information via msinfo32
    $tempFile = "$env:TEMP\msinfo_report_$(Get-Random).txt"
    try {
        $proc = Start-Process -FilePath "msinfo32.exe" -ArgumentList "/report", "`"$tempFile`"", "/nfo", "`"$tempFile`"" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
        
        # Wait for file to be created (up to 5 seconds)
        $maxWait = 10
        $waited = 0
        while (-not (Test-Path $tempFile) -and $waited -lt $maxWait) {
            Start-Sleep -Milliseconds 500
            $waited++
        }
        
        if (Test-Path $tempFile) {
            Start-Sleep -Milliseconds 1000
            $content = Get-Content $tempFile -ErrorAction SilentlyContinue
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            
            foreach ($line in $content) {
                if ($line -match "Kernel DMA Protection\s*:\s*(\S+)") {
                    $result = $matches[1].Trim()
                    if ($result -eq "Enabled" -or $result -eq "On") {
                        return $true
                    }
                    if ($result -eq "Disabled" -or $result -eq "Off") {
                        return $false
                    }
                    if ($result -match "Not Available|Not Supported|Unsupported") {
                        return $null
                    }
                }
            }
        }
    } catch {
        Write-Warning "Error checking msinfo32: $($_.Exception.Message)"
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
    
    # If registry path doesn't exist, feature is unsupported
    if (-not $Global:RegistryPathCache[$regPath]) {
        return $null
    }
    
    # Default: assume disabled (not unsupported, since registry path exists)
    return $false
}

function Get-SecureBootStatus {
    # Compatible with Windows 8+ and UEFI systems
    try {
        # Check if command is available (Windows 8+)
        $winVersion = Test-WindowsVersion
        if ([int]$winVersion.MajorVersion -lt 6) {
            return $false
        }
        
        # Try Secure Boot check (requires UEFI)
        if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            if (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
                return $true
            } else {
                return $false
            }
        } else {
            # Command not available - likely legacy BIOS or older Windows
            return $false
        }
    } catch {
        # Silently fail - Secure Boot not available on this system
        return $false
    }
}

function Get-CoreIsolationStatus {
    # Checks Core Isolation / Memory Integrity (HVCI) status
    # Returns: $true if enabled, $false if disabled, $null if unsupported
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        if (Test-Path $regPath) {
            $regValue = Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue
            if ($regValue) {
                if ($regValue.Enabled -eq 1) {
                    return $true
                } elseif ($regValue.Enabled -eq 0) {
                    return $false
                }
            }
        } else {
            return $null
        }
    } catch {
        Write-Warning "Error checking Core Isolation status: $($_.Exception.Message). Try running as Administrator."
    }
    
    # Alternative check via WMI (Windows 10 1803+)
    try {
        $hvciStatus = Get-CimInstanceCompat -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard"
        if ($hvciStatus) {
            $hvciValue = $hvciStatus | Select-Object -ExpandProperty HypervisorEnforcedCodeIntegrityStatus -ErrorAction SilentlyContinue
            if ($hvciValue -eq 1 -or $hvciValue -eq 2) {
                return $true
            } elseif ($hvciValue -eq 0) {
                return $false
            }
        }
    } catch {
        # DeviceGuard namespace may not exist on older Windows - expected behavior
    }
    
    return $null
}

function Get-TamperProtectionStatus {
    # Checks Tamper Protection status (Windows 10 1903+)
    # Returns: $true if enabled, $false if disabled, $null if unsupported
    try {
        # Check if Defender cmdlets are available
        if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
            # Defender cmdlets not available - try registry only
            return $null
        }
        
        # Import Defender module if available
        $defenderModule = Get-Module -ListAvailable -Name Defender -ErrorAction SilentlyContinue
        if ($defenderModule) {
            Import-Module Defender -ErrorAction SilentlyContinue
        }
        
        # Primary method: Use Get-MpComputerStatus (most reliable)
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            $isTamperProtected = $defenderStatus.IsTamperProtected
            if ($isTamperProtected -eq $true) {
                return $true
            } elseif ($isTamperProtected -eq $false) {
                return $false
            }
        }
    } catch {
        # Defender may not be available on this system - fall through to registry check
    }
    
    # Fallback method: Check registry
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
        if (Test-Path $regPath) {
            $regValue = Get-ItemProperty -Path $regPath -Name "TamperProtection" -ErrorAction SilentlyContinue
            if ($null -ne $regValue -and $null -ne $regValue.TamperProtection) {
                # Registry values: 0 = Off, 1 = On (managed), 2 = On (user), 5 = On
                if ($regValue.TamperProtection -eq 5 -or $regValue.TamperProtection -eq 1 -or $regValue.TamperProtection -eq 2) {
                    return $true
                } elseif ($regValue.TamperProtection -eq 0) {
                    return $false
                }
            }
        }
    } catch {
        Write-Warning "Error checking Tamper Protection registry: $($_.Exception.Message). Try running as Administrator."
    }
    
    return $null
}

function Get-DefenderRealTimeStatus {
    # Checks Windows Defender Real-Time Protection status
    # Returns: $true if enabled, $false if disabled, $null if unsupported
    try {
        # Check if Defender cmdlets are available
        if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
            # Defender cmdlets not available - try registry only
            return $null
        }
        
        # Import Defender module if available
        $defenderModule = Get-Module -ListAvailable -Name Defender -ErrorAction SilentlyContinue
        if ($defenderModule) {
            Import-Module Defender -ErrorAction SilentlyContinue
        }
        
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            if ($defenderStatus.RealTimeProtectionEnabled) {
                return $true
            } else {
                return $false
            }
        }
    } catch {
        # Defender may not be available - fall through to registry check
    }
    
    # Alternative check via registry
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
        if (Test-Path $regPath) {
            $disabledValue = Get-ItemProperty -Path $regPath -Name "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue
            if ($null -ne $disabledValue) {
                if ($disabledValue.DisableRealtimeMonitoring -eq 0) {
                    return $true
                } else {
                    return $false
                }
            }
        }
    } catch {}
    
    return $null
}

function Test-DeviceForSuspicion {
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Name,
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Description,
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]$HardwareIDs
    )
    
    # Returns: "NONE", "SUSPICIOUS", or "CONCRETE"
    if ([string]::IsNullOrWhiteSpace($Name)) {
        $Name = "[No Name]"
    }
    if ([string]::IsNullOrWhiteSpace($Description)) {
        $Description = "[No Description]"
    }
    
    $vendorMatch = $false
    $keywordMatch = $false
    
    # Check hardware IDs against known suspicious vendors (using compiled regex)
    if ($HardwareIDs) {
        foreach ($hwid in $HardwareIDs) {
            if ($Global:VendorRegex.IsMatch($hwid)) {
                $vendorMatch = $true
                break
            }
        }
    }
    
    # Search for suspicious keywords in device name/description
    foreach ($keyword in $Global:SuspiciousKeywords) {
        # Special handling for "DMA" to avoid false positives
        if ($keyword -eq "DMA") {
            if ($Global:DmaKeywordRegex.IsMatch($Name) -or $Global:DmaKeywordRegex.IsMatch($Description)) {
                if (-not ($Global:DmaExcludeRegex.IsMatch($Name) -or $Global:DmaExcludeRegex.IsMatch($Description))) {
                    $keywordMatch = $true
                    break
                }
            }
        } else {
            if ($Name -imatch $keyword -or $Description -imatch $keyword) {
                $keywordMatch = $true
                break
            }
        }
    }
    
    if ($vendorMatch -and $keywordMatch) {
        return "CONCRETE"
    } elseif ($vendorMatch -or $keywordMatch) {
        return "SUSPICIOUS"
    }
    return "NONE"
}

#endregion

#region Device Scanning Functions

function Get-SuspiciousPresentPCIDevices {
    Write-ProgressStep -Activity "Scanning Devices" -Status "Checking present PCI devices..." -PercentComplete 10
    Write-Host "   [Scanning] Checking present PCI devices..." -ForegroundColor Gray
    $deviceList = Get-CimInstanceCompat -ClassName "Win32_PnPEntity"
    $foundDevices = @()
    $totalDevices = $deviceList.Count
    $processed = 0
    
    foreach ($device in $deviceList) {
        $processed++
        if ($processed % 50 -eq 0) {
            Write-ProgressStep -Activity "Scanning Devices" -Status "Processing device $processed of $totalDevices..." -PercentComplete (10 + ($processed / $totalDevices * 20))
            Write-Host "   [Progress] Processing device $processed of $totalDevices..." -ForegroundColor Gray
        }
        
        $evidenceLevel = Test-DeviceForSuspicion -Name $device.Name -Description $device.Description -HardwareIDs $device.HardwareID
        if ($evidenceLevel -ne "NONE") {
            $foundDevices += [PSCustomObject]@{
                Device = $device
                Evidence = $evidenceLevel
                DeviceName = $device.Name
                DeviceDescription = $device.Description
                HardwareIDs = $device.HardwareID
                Status = $device.Status
                ClassGuid = $device.ClassGuid
            }
        }
    }
    return $foundDevices
}

function Get-SuspiciousHiddenDevices {
    Write-ProgressStep -Activity "Scanning Devices" -Status "Checking hidden/removed devices..." -PercentComplete 35
    Write-Host "   [Scanning] Checking hidden/removed devices..." -ForegroundColor Gray
    
    # Check if Get-PnpDevice is available (Windows 8+)
    if (-not (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue)) {
        # Older Windows - return empty array
        return @()
    }
    
    $allDevices = Get-PnpDevice -PresentOnly:$false -ErrorAction SilentlyContinue
    $hiddenResults = @()
    $totalDevices = ($allDevices | Where-Object { $_.Status -eq "Unknown" -or $_.Status -eq "Error" }).Count
    $processed = 0
    
    foreach ($device in $allDevices) {
        if ($device.Status -eq "Unknown" -or $device.Status -eq "Error") {
            $processed++
            if ($processed % 10 -eq 0 -and $totalDevices -gt 0) {
                Write-ProgressStep -Activity "Scanning Devices" -Status "Processing hidden device $processed of $totalDevices..." -PercentComplete (35 + ($processed / $totalDevices * 15))
                Write-Host "   [Progress] Processing hidden device $processed of $totalDevices..." -ForegroundColor Gray
            }
            
            try {
                $cimDevice = Get-CimInstanceCompat -ClassName "Win32_PnPEntity" -Filter "DeviceID='$($device.InstanceId.Replace('\', '\\'))'"
                if ($cimDevice) {
                    $evidenceLevel = Test-DeviceForSuspicion -Name $cimDevice.Name -Description $cimDevice.Description -HardwareIDs $cimDevice.HardwareID
                    if ($evidenceLevel -ne "NONE") {
                        $hiddenResults += [PSCustomObject]@{
                            PnpDevice = $device
                            CimDevice = $cimDevice
                            Evidence = $evidenceLevel
                            DeviceName = $cimDevice.Name
                            DeviceDescription = $cimDevice.Description
                            HardwareIDs = $cimDevice.HardwareID
                            Status = $device.Status
                            InstanceId = $device.InstanceId
                        }
                    }
                }
            } catch {
                # Skip devices that can't be queried
            }
        }
    }
    return $hiddenResults
}

function Get-SuspiciousRegistryPCIDevices {
    Write-ProgressStep -Activity "Scanning Devices" -Status "Checking registry PCI entries..." -PercentComplete 55
    Write-Host "   [Scanning] Checking registry PCI entries..." -ForegroundColor Gray
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"
    $registryResults = @()
    
    if (Test-Path $registryPath) {
        $registryItems = Get-ChildItem $registryPath -ErrorAction SilentlyContinue
        $totalItems = $registryItems.Count
        $processed = 0
        
        foreach ($item in $registryItems) {
            $processed++
            if ($processed % 100 -eq 0) {
                Write-ProgressStep -Activity "Scanning Devices" -Status "Processing registry entry $processed of $totalItems..." -PercentComplete (55 + ($processed / $totalItems * 10))
                Write-Host "   [Progress] Processing registry entry $processed of $totalItems..." -ForegroundColor Gray
            }
            
            if ($Global:VendorRegex.IsMatch($item.PSChildName)) {
                $registryResults += [PSCustomObject]@{
                    RegistryKey = $item.PSPath
                    Identifier = $item.PSChildName
                    Evidence = "SUSPICIOUS"
                    LastWriteTime = $item.LastWriteTime
                }
            }
        }
    } else {
        Write-Warning "Registry path $registryPath not found. This may require Administrator privileges."
    }
    return $registryResults
}

#endregion

#region Log Analysis Functions

function Parse-SetupAPILog {
    Write-ProgressStep -Activity "Analyzing Logs" -Status "Parsing SetupAPI log..." -PercentComplete 70
    Write-Host "   [Analyzing] Parsing SetupAPI log..." -ForegroundColor Gray
    # Analyzes SetupAPI log for suspicious entries (optimized with streaming)
    $safePatterns = @("wdma_usb", "wdmaudio.inf", "UDMA", "IDE DMA", "DMA Controller", "Direct Memory Access Controller", "DMA Channel", "ATAPI DMA", "Toshiba")
    $logFile = "C:\Windows\Inf\setupapi.dev.log"
    $suspCount = 0
    $concreteCount = 0
    $suspiciousLines = @()
    $concreteLines = @()
    
    if (Test-Path $logFile) {
        try {
            # Use streaming for large files to optimize memory
            $lineNumber = 0
            $fileInfo = Get-Item $logFile
            $totalLines = if ($fileInfo.Length -gt 0) { [math]::Min(100000, (Get-Content $logFile -ReadCount 0 | Measure-Object -Line).Lines) } else { 1000 }
            
            Get-Content $logFile -ReadCount 1000 -ErrorAction SilentlyContinue | ForEach-Object {
                $chunk = $_
                foreach ($line in $chunk) {
                    $lineNumber++
                    if ($lineNumber % 5000 -eq 0) {
                        $percent = 70 + ([math]::Min(90, ($lineNumber / $totalLines * 20)))
                        Write-ProgressStep -Activity "Analyzing Logs" -Status "Processing line $lineNumber of ~$totalLines..." -PercentComplete $percent
                        Write-Host "   [Progress] Processing line $lineNumber of ~$totalLines..." -ForegroundColor Gray
                    }
                    
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    
                    # Skip whitelisted patterns
                    $shouldSkip = $false
                    foreach ($pattern in $safePatterns) {
                        if ($line -imatch $pattern) {
                            $shouldSkip = $true
                            break
                        }
                    }
                    if ($shouldSkip) { continue }
                    
                    # Check for vendor IDs (using compiled regex)
                    $foundVendor = $Global:VendorRegex.IsMatch($line)
                    
                    # Check for keywords
                    $foundKeyword = $false
                    foreach ($keyword in $Global:SuspiciousKeywords) {
                        if ($keyword -eq "DMA") {
                            if ($Global:DmaKeywordRegex.IsMatch($line) -and -not $Global:DmaExcludeRegex.IsMatch($line)) {
                                $foundKeyword = $true
                                break
                            }
                        } else {
                            if ($line -imatch $keyword) {
                                $foundKeyword = $true
                                break
                            }
                        }
                    }
                    
                    if ($foundVendor -and $foundKeyword) {
                        $concreteCount++
                        $concreteLines += $line
                    } elseif ($foundVendor -or $foundKeyword) {
                        $suspCount++
                        $suspiciousLines += $line
                    }
                }
            }
        } catch {
            Write-Warning "Error reading SetupAPI log: $($_.Exception.Message). The log file may be locked or inaccessible. Try running as Administrator."
        }
    } else {
        Write-Warning "SetupAPI log not found at $logFile. This may indicate the system hasn't installed devices recently."
    }
    return [PSCustomObject]@{
        SuspiciousCount = $suspCount
        ConcreteCount = $concreteCount
        SuspiciousLines = $suspiciousLines
        ConcreteLines = $concreteLines
    }
}

function Check-ThunderboltEvents {
    Write-ProgressStep -Activity "Analyzing Logs" -Status "Checking Thunderbolt events..." -PercentComplete 92
    Write-Host "   [Analyzing] Checking Thunderbolt events..." -ForegroundColor Gray
    $thunderboltEvents = @()
    try {
        # Check if Thunderbolt log exists (may not exist on systems without Thunderbolt)
        $logExists = Get-WinEvent -ListLog "Microsoft-Windows-Thunderbolt/Operational" -ErrorAction SilentlyContinue
        if (-not $logExists) {
            # Log doesn't exist - system likely doesn't have Thunderbolt
            return $thunderboltEvents
        }
        
        $events = Get-WinEvent -LogName "Microsoft-Windows-Thunderbolt/Operational" -ErrorAction SilentlyContinue -MaxEvents 1000
        if ($events) {
            foreach ($event in $events) {
                if ($event.Message -match "(unauthorized|failed|blocked)") {
                    $thunderboltEvents += [PSCustomObject]@{
                        Event = $event
                        TimeCreated = $event.TimeCreated
                        Id = $event.Id
                        Message = $event.Message
                    }
                }
            }
        }
    } catch {
        Write-Warning "Error checking Thunderbolt events: $($_.Exception.Message). Thunderbolt log may not exist on this system."
    }
    return $thunderboltEvents
}

function Get-EDIDData {
    Write-ProgressStep -Activity "Analyzing Logs" -Status "Retrieving EDID monitor data..." -PercentComplete 95
    Write-Host "   [Analyzing] Retrieving EDID monitor data..." -ForegroundColor Gray
    $monitorList = @()
    $displayKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"
    if (Test-Path $displayKey) {
        $displayItems = Get-ChildItem $displayKey -ErrorAction SilentlyContinue
        foreach ($item in $displayItems) {
            foreach ($subItem in Get-ChildItem $item.PSPath -ErrorAction SilentlyContinue) {
                try {
                    $deviceParams = Get-ItemProperty -Path "$($subItem.PSPath)\Device Parameters" -ErrorAction SilentlyContinue
                    if ($deviceParams -and $deviceParams.DeviceID) {
                        $monitorList += [PSCustomObject]@{
                            DevicePath = $subItem.PSPath
                            DeviceID = $deviceParams.DeviceID
                            MonitorName = $subItem.PSChildName
                            LastWriteTime = $subItem.LastWriteTime
                        }
                    }
                } catch {
                    # Skip monitors that can't be accessed
                }
            }
        }
    }
    
    # Enhanced EDID analysis - check for mismatches
    if ($monitorList.Count -gt 1) {
        $uniqueIds = $monitorList | Select-Object -ExpandProperty DeviceID -Unique
        if ($uniqueIds.Count -ne $monitorList.Count) {
            Write-Warning "Multiple monitors detected with potential EDID mismatches. This could indicate DMA device spoofing."
        }
    }
    
    return $monitorList
}

#endregion

#region Export Functions

function Export-ResultsToJSON {
    param(
        [object]$ScanResults,
        [string]$FilePath
    )
    $jsonData = @{
        ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        SystemInfo = @{
            ComputerName = $env:COMPUTERNAME
            OSVersion = (Get-CimInstanceCompat -ClassName "Win32_OperatingSystem").Version
            SecureBoot = $ScanResults.SecureBoot
            KernelDMA = $ScanResults.KernelDMA
            CoreIsolation = $ScanResults.CoreIsolation
            TamperProtection = $ScanResults.TamperProtection
            DefenderRealTime = $ScanResults.DefenderRealTime
        }
        Results = @{
            FinalColor = $ScanResults.FinalColor
            DefiniteItems = $ScanResults.DefiniteItems
            SuspiciousItems = $ScanResults.SuspiciousItems
            PresentPCIDevices = $ScanResults.PresentDevices
            HiddenDevices = $ScanResults.HiddenDevices
            RegistryDevices = $ScanResults.RegistryDevices
            SetupAPILines = @{
                Suspicious = $ScanResults.SetupAPISuspicious
                Concrete = $ScanResults.SetupAPIConcrete
                SuspiciousLines = $ScanResults.SetupAPISuspiciousLines
                ConcreteLines = $ScanResults.SetupAPIConcreteLines
            }
            ThunderboltEvents = $ScanResults.ThunderboltEvents
            EDIDMonitors = $ScanResults.EDIDMonitors
        }
    }
    
    $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath "$FilePath.json" -Encoding UTF8
    Write-Host "Results exported to JSON: $FilePath.json" -ForegroundColor Green
}

function Export-ResultsToHTML {
    param(
        [object]$ScanResults,
        [string]$FilePath
    )
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>DMA Detection Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { background: white; margin: 20px 0; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .red { color: #e74c3c; font-weight: bold; }
        .yellow { color: #f39c12; font-weight: bold; }
        .green { color: #27ae60; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; }
        .device-detail { margin: 10px 0; padding: 10px; background: #ecf0f1; border-left: 4px solid #3498db; }
    </style>
</head>
<body>
    <div class="header">
        <h1>DMA Detection Scan Report</h1>
        <p>Scan Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>Computer: $env:COMPUTERNAME</p>
    </div>
    
    <div class="section">
        <h2>Final Result</h2>
        <p class="$($ScanResults.FinalColor.ToLower())">Status: $($ScanResults.FinalColor)</p>
        <p>Definite Items: $($ScanResults.DefiniteItems)</p>
        <p>Suspicious Items: $($ScanResults.SuspiciousItems)</p>
    </div>
    
    <div class="section">
        <h2>Security Status</h2>
        <p>Secure Boot: $($ScanResults.SecureBoot)</p>
        <p>Kernel DMA Protection: $($ScanResults.KernelDMA)</p>
        <p>Core Isolation (HVCI): $($ScanResults.CoreIsolation)</p>
        <p>Tamper Protection: $($ScanResults.TamperProtection)</p>
        <p>Defender Real-Time: $($ScanResults.DefenderRealTime)</p>
    </div>
    
    <div class="section">
        <h2>Device Scan Results</h2>
        <p>Present PCI Devices: $($ScanResults.PresentDevices.Count)</p>
        <p>Hidden Devices: $($ScanResults.HiddenDevices.Count)</p>
        <p>Registry Entries: $($ScanResults.RegistryDevices.Count)</p>
    </div>
    
    <div class="section">
        <h2>Log Analysis</h2>
        <p>SetupAPI Suspicious Lines: $($ScanResults.SetupAPISuspicious)</p>
        <p>SetupAPI Concrete Lines: $($ScanResults.SetupAPIConcrete)</p>
        <p>Thunderbolt Events: $($ScanResults.ThunderboltEvents.Count)</p>
        <p>EDID Monitors: $($ScanResults.EDIDMonitors.Count)</p>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath "$FilePath.html" -Encoding UTF8
    Write-Host "Results exported to HTML: $FilePath.html" -ForegroundColor Green
}

function Export-ResultsToTXT {
    param(
        [object]$ScanResults,
        [string]$FilePath
    )
    $report = @"
DMA Detection Scan Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer: $env:COMPUTERNAME

FINAL RESULT: $($ScanResults.FinalColor)
Definite Items: $($ScanResults.DefiniteItems)
Suspicious Items: $($ScanResults.SuspiciousItems)

SECURITY STATUS:
Secure Boot: $($ScanResults.SecureBoot)
Kernel DMA Protection: $($ScanResults.KernelDMA)
Core Isolation (HVCI): $($ScanResults.CoreIsolation)
Tamper Protection: $($ScanResults.TamperProtection)
Defender Real-Time: $($ScanResults.DefenderRealTime)

DEVICE SCAN:
Present PCI Devices: $($ScanResults.PresentDevices.Count)
Hidden Devices: $($ScanResults.HiddenDevices.Count)
Registry Entries: $($ScanResults.RegistryDevices.Count)

LOG ANALYSIS:
SetupAPI Suspicious: $($ScanResults.SetupAPISuspicious)
SetupAPI Concrete: $($ScanResults.SetupAPIConcrete)
Thunderbolt Events: $($ScanResults.ThunderboltEvents.Count)
EDID Monitors: $($ScanResults.EDIDMonitors.Count)
"@
    
    $report | Out-File -FilePath "$FilePath.txt" -Encoding UTF8
    Write-Host "Results exported to TXT: $FilePath.txt" -ForegroundColor Green
}

#endregion

#region Main Execution

Write-Host "`nStep 1: Security Checks..." -ForegroundColor Cyan
$secureBootEnabled = Get-SecureBootStatus
$kernelDmaStatus = Get-KernelDMAProtectionStatus
$coreIsolationStatus = Get-CoreIsolationStatus
$tamperProtectionStatus = Get-TamperProtectionStatus
$defenderRealTimeStatus = Get-DefenderRealTimeStatus

$secureBootText = if ($secureBootEnabled) { "ENABLED" } else { "DISABLED" }

# Handle Kernel DMA status (can be $true, $false, or $null)
if ($kernelDmaStatus -eq $true) {
    $kernelDmaText = "ENABLED"
    $kernelDmaEnabled = $true
} elseif ($kernelDmaStatus -eq $false) {
    $kernelDmaText = "DISABLED"
    $kernelDmaEnabled = $false
} else {
    $kernelDmaText = "UNSUPPORTED"
    $kernelDmaEnabled = $false
}

# Handle Core Isolation status
if ($coreIsolationStatus -eq $true) {
    $coreIsolationText = "ENABLED"
} elseif ($coreIsolationStatus -eq $false) {
    $coreIsolationText = "DISABLED"
} else {
    $coreIsolationText = "DISABLED"
}

# Handle Tamper Protection status
if ($tamperProtectionStatus -eq $true) {
    $tamperProtectionText = "ENABLED"
} elseif ($tamperProtectionStatus -eq $false) {
    $tamperProtectionText = "DISABLED"
} else {
    $tamperProtectionText = "DISABLED"
}

# Handle Windows Defender Real-Time Protection status
if ($defenderRealTimeStatus -eq $true) {
    $defenderRealTimeText = "ENABLED"
} elseif ($defenderRealTimeStatus -eq $false) {
    $defenderRealTimeText = "DISABLED"
} else {
    $defenderRealTimeText = "DISABLED"
}

if ($secureBootEnabled) {
    Write-Host " - Secure Boot: ENABLED" -ForegroundColor Green
} else {
    Write-Host " - Secure Boot: DISABLED" -ForegroundColor Yellow
}

if ($kernelDmaStatus -eq $true) {
    Write-Host " - Kernel DMA Protection: ENABLED" -ForegroundColor Green
} elseif ($kernelDmaStatus -eq $false) {
    Write-Host " - Kernel DMA Protection: DISABLED" -ForegroundColor Yellow
} else {
    Write-Host " - Kernel DMA Protection: UNSUPPORTED (hardware/firmware limitation)" -ForegroundColor Yellow
}

if ($coreIsolationStatus -eq $true) {
    Write-Host " - Core Isolation / Memory Integrity (HVCI): ENABLED" -ForegroundColor Green
} else {
    Write-Host " - Core Isolation / Memory Integrity (HVCI): DISABLED" -ForegroundColor Yellow
}

if ($tamperProtectionStatus -eq $true) {
    Write-Host " - Tamper Protection: ENABLED" -ForegroundColor Green
} else {
    Write-Host " - Tamper Protection: DISABLED" -ForegroundColor Yellow
}

if ($defenderRealTimeStatus -eq $true) {
    Write-Host " - Windows Defender Real-Time Protection: ENABLED" -ForegroundColor Green
} else {
    Write-Host " - Windows Defender Real-Time Protection: DISABLED" -ForegroundColor Yellow
}

Write-Host "`nStep 2: Device & Log Scans..." -ForegroundColor Cyan

# Scan present PCI devices
try {
    $presentDevices = Get-SuspiciousPresentPCIDevices
    $concretePresent = $presentDevices | Where-Object { $_.Evidence -eq "CONCRETE" }
    $suspiciousPresent = $presentDevices | Where-Object { $_.Evidence -eq "SUSPICIOUS" }
    Write-Host " - Present PCI: $($presentDevices.Count) suspicious device(s)."
    
    # Display device details if found
    if ($presentDevices.Count -gt 0) {
        Write-Host "`n   Device Details:" -ForegroundColor Cyan
        foreach ($device in $presentDevices) {
            Write-Host "     [$($device.Evidence)] $($device.DeviceName)" -ForegroundColor $(if ($device.Evidence -eq "CONCRETE") { "Red" } else { "Yellow" })
            if ($device.DeviceDescription) {
                Write-Host "       Description: $($device.DeviceDescription)" -ForegroundColor Gray
            }
            if ($device.HardwareIDs) {
                Write-Host "       Hardware IDs: $($device.HardwareIDs -join ', ')" -ForegroundColor Gray
            }
            Write-Host "       Status: $($device.Status)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host " - Present PCI: Error scanning devices - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   Troubleshooting: Ensure you have Administrator privileges and WMI service is running." -ForegroundColor Yellow
    $presentDevices = @()
    $concretePresent = @()
    $suspiciousPresent = @()
}

# Scan hidden/removed devices
try {
    $hiddenDevices = Get-SuspiciousHiddenDevices
    $concreteHidden = $hiddenDevices | Where-Object { $_.Evidence -eq "CONCRETE" }
    $suspiciousHidden = $hiddenDevices | Where-Object { $_.Evidence -eq "SUSPICIOUS" }
    Write-Host " - Hidden PCI: $($hiddenDevices.Count) suspicious device(s)."
    
    # Display hidden device details if found
    if ($hiddenDevices.Count -gt 0) {
        Write-Host "`n   Hidden Device Details:" -ForegroundColor Cyan
        foreach ($device in $hiddenDevices) {
            Write-Host "     [$($device.Evidence)] $($device.DeviceName)" -ForegroundColor $(if ($device.Evidence -eq "CONCRETE") { "Red" } else { "Yellow" })
            Write-Host "       Instance ID: $($device.InstanceId)" -ForegroundColor Gray
            Write-Host "       Status: $($device.Status)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host " - Hidden PCI: Error scanning hidden devices - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   Troubleshooting: Hidden device enumeration requires Administrator privileges." -ForegroundColor Yellow
    $hiddenDevices = @()
    $concreteHidden = @()
    $suspiciousHidden = @()
}

# Scan registry PCI entries
try {
    $registryDevices = Get-SuspiciousRegistryPCIDevices
    Write-Host " - Registry PCI: $($registryDevices.Count) suspicious entry/entries."
    
    # Display registry device details if found
    if ($registryDevices.Count -gt 0) {
        Write-Host "`n   Registry Entry Details:" -ForegroundColor Cyan
        foreach ($entry in $registryDevices) {
            Write-Host "     [SUSPICIOUS] $($entry.Identifier)" -ForegroundColor Yellow
            Write-Host "       Registry Path: $($entry.RegistryKey)" -ForegroundColor Gray
            Write-Host "       Last Modified: $($entry.LastWriteTime)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host " - Registry PCI: Error scanning registry - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   Troubleshooting: Registry access requires Administrator privileges." -ForegroundColor Yellow
    $registryDevices = @()
}

Write-Progress -Activity "Scanning" -Completed

# Analyze SetupAPI log
try {
    $setupLogInfo = Parse-SetupAPILog
    Write-Host " - SetupAPI: $($setupLogInfo.SuspiciousCount + $setupLogInfo.ConcreteCount) total suspicious lines."
    Write-Host "   (Suspicious: $($setupLogInfo.SuspiciousCount), Concrete: $($setupLogInfo.ConcreteCount))"
    
    # Display concrete (definite) evidence lines
    if ($setupLogInfo.ConcreteLines.Count -gt 0) {
        Write-Host "`n   CONCRETE evidence lines:" -ForegroundColor Red
        foreach ($line in $setupLogInfo.ConcreteLines) {
            # Truncate very long lines for readability
            $displayLine = if ($line.Length -gt 120) { $line.Substring(0, 120) + "..." } else { $line }
            Write-Host "     - $displayLine" -ForegroundColor Red
        }
    }
    
    # Display suspicious lines
    if ($setupLogInfo.SuspiciousLines.Count -gt 0) {
        Write-Host "`n   SUSPICIOUS lines:" -ForegroundColor Yellow
        foreach ($line in $setupLogInfo.SuspiciousLines) {
            # Truncate very long lines for readability
            $displayLine = if ($line.Length -gt 120) { $line.Substring(0, 120) + "..." } else { $line }
            Write-Host "     - $displayLine" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host " - SetupAPI: Error parsing log - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   Troubleshooting: The SetupAPI log may be locked. Close Device Manager and try again." -ForegroundColor Yellow
    $setupLogInfo = [PSCustomObject]@{ SuspiciousCount = 0; ConcreteCount = 0; SuspiciousLines = @(); ConcreteLines = @() }
}

# Check Thunderbolt events
try {
    $thunderboltResults = Check-ThunderboltEvents
    Write-Host " - Thunderbolt events: $($thunderboltResults.Count) unauthorized/blocked."
    
    if ($thunderboltResults.Count -gt 0) {
        Write-Host "`n   Thunderbolt Event Details:" -ForegroundColor Cyan
        foreach ($event in $thunderboltResults) {
            Write-Host "     Event ID: $($event.Id) - $($event.TimeCreated)" -ForegroundColor Yellow
            Write-Host "       $($event.Message.Substring(0, [Math]::Min(100, $event.Message.Length)))" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host " - Thunderbolt events: Error checking events - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   Troubleshooting: Thunderbolt log may not exist on systems without Thunderbolt ports." -ForegroundColor Yellow
    $thunderboltResults = @()
}

# Get EDID monitor data
try {
    $edidMonitors = Get-EDIDData
    Write-Host " - EDID monitors found: $($edidMonitors.Count)"
    
    if ($edidMonitors.Count -gt 0) {
        Write-Host "`n   Monitor Details:" -ForegroundColor Cyan
        foreach ($monitor in $edidMonitors) {
            Write-Host "     Monitor: $($monitor.MonitorName)" -ForegroundColor Gray
            Write-Host "       Device ID: $($monitor.DeviceID)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host " - EDID monitors: Error retrieving data - $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   Troubleshooting: Monitor enumeration requires Administrator privileges." -ForegroundColor Yellow
    $edidMonitors = @()
}

Write-Progress -Activity "Scanning" -Completed

# Calculate totals
$totalSuspicious = 0
$totalConcrete = 0
$totalSuspicious += $suspiciousPresent.Count
$totalConcrete += $concretePresent.Count
$totalSuspicious += $suspiciousHidden.Count
$totalConcrete += $concreteHidden.Count
$totalSuspicious += $registryDevices.Count
$totalSuspicious += $setupLogInfo.SuspiciousCount
$totalConcrete += $setupLogInfo.ConcreteCount
if ($thunderboltResults.Count -gt 0) { $totalSuspicious++ }
if ($edidMonitors.Count -gt 1) { $totalSuspicious++ }

Write-Host "`nStep 3: Determining Final Color..." -ForegroundColor Cyan
$resultColor = "Green"
if ($totalConcrete -gt 0) {
    $resultColor = "Red"
} elseif ($totalSuspicious -gt 0) {
    if ($kernelDmaEnabled) {
        $resultColor = "Red"
    } else {
        $resultColor = "Yellow"
    }
}

Write-Host "`n===== FINAL REPORT =====" -ForegroundColor Cyan

# Color-coded summary table
Write-Host "`nSummary Table:" -ForegroundColor Cyan
$summaryTable = @(
    [PSCustomObject]@{ Category = "Final Result"; Value = $resultColor; Status = $resultColor }
    [PSCustomObject]@{ Category = "Definite Items"; Value = $totalConcrete; Status = if ($totalConcrete -gt 0) { "Red" } else { "Green" } }
    [PSCustomObject]@{ Category = "Suspicious Items"; Value = $totalSuspicious; Status = if ($totalSuspicious -gt 0) { "Yellow" } else { "Green" } }
    [PSCustomObject]@{ Category = "Secure Boot"; Value = $secureBootText; Status = if ($secureBootEnabled) { "Green" } else { "Yellow" } }
    [PSCustomObject]@{ Category = "Kernel DMA"; Value = $kernelDmaText; Status = if ($kernelDmaStatus -eq $true) { "Green" } elseif ($kernelDmaStatus -eq $false) { "Yellow" } else { "Yellow" } }
    [PSCustomObject]@{ Category = "Core Isolation (HVCI)"; Value = $coreIsolationText; Status = if ($coreIsolationStatus -eq $true) { "Green" } elseif ($coreIsolationStatus -eq $false) { "Yellow" } else { "Yellow" } }
    [PSCustomObject]@{ Category = "Tamper Protection"; Value = $tamperProtectionText; Status = if ($tamperProtectionStatus -eq $true) { "Green" } elseif ($tamperProtectionStatus -eq $false) { "Yellow" } else { "Yellow" } }
    [PSCustomObject]@{ Category = "Defender Real-Time"; Value = $defenderRealTimeText; Status = if ($defenderRealTimeStatus -eq $true) { "Green" } elseif ($defenderRealTimeStatus -eq $false) { "Yellow" } else { "Yellow" } }
    [PSCustomObject]@{ Category = "Present PCI"; Value = $presentDevices.Count; Status = if ($presentDevices.Count -gt 0) { "Yellow" } else { "Green" } }
    [PSCustomObject]@{ Category = "Hidden PCI"; Value = $hiddenDevices.Count; Status = if ($hiddenDevices.Count -gt 0) { "Yellow" } else { "Green" } }
    [PSCustomObject]@{ Category = "Registry PCI"; Value = $registryDevices.Count; Status = if ($registryDevices.Count -gt 0) { "Yellow" } else { "Green" } }
    [PSCustomObject]@{ Category = "SetupAPI Lines"; Value = ($setupLogInfo.SuspiciousCount + $setupLogInfo.ConcreteCount); Status = if (($setupLogInfo.SuspiciousCount + $setupLogInfo.ConcreteCount) -gt 0) { "Yellow" } else { "Green" } }
    [PSCustomObject]@{ Category = "Thunderbolt Events"; Value = $thunderboltResults.Count; Status = if ($thunderboltResults.Count -gt 0) { "Yellow" } else { "Green" } }
    [PSCustomObject]@{ Category = "EDID Monitors"; Value = $edidMonitors.Count; Status = if ($edidMonitors.Count -gt 1) { "Yellow" } else { "Green" } }
)

foreach ($row in $summaryTable) {
    $color = switch ($row.Status) {
        "Red" { "Red" }
        "Yellow" { "Yellow" }
        default { "Green" }
    }
    Write-Host ("  {0,-20} {1}" -f $row.Category, $row.Value) -ForegroundColor $color
}

switch ($resultColor) {
    "Red" {
        if ($totalConcrete -gt 0) {
            Write-Host "`nRED: 100% EVIDENCE OF DMA CHEAT DETECTED!" -ForegroundColor Red
        } else {
            Write-Host "`nRED: Suspicious devices found, Kernel DMA ON => Definite DMA." -ForegroundColor Red
        }
    }
    "Yellow" {
        Write-Host "`nYELLOW: Possible DMA cheat detected (system is vulnerable)." -ForegroundColor Yellow
    }
    "Green" {
        Write-Host "`nGREEN: No DMA cheat evidence found." -ForegroundColor Green
    }
}

# Create summary message (clean summary for webhook - no progress messages included)
$reportSummary = "DMA Detection Summary:`n" +
    "Final Color: $resultColor`n" +
    "Definite Items: $totalConcrete`n" +
    "Suspicious Items: $totalSuspicious`n" +
    "`nSecurity Status:`n" +
    "Secure Boot: $secureBootText`n" +
    "Kernel DMA Protection: $kernelDmaText`n" +
    "Core Isolation (HVCI): $coreIsolationText`n" +
    "Tamper Protection: $tamperProtectionText`n" +
    "Defender Real-Time: $defenderRealTimeText`n" +
    "`nScan Results:`n" +
    "Present PCI suspicious: $($presentDevices.Count), " +
    "Hidden PCI suspicious: $($hiddenDevices.Count), " +
    "Registry suspicious: $($registryDevices.Count), " +
    "SetupAPI suspicious lines: $($setupLogInfo.SuspiciousCount + $setupLogInfo.ConcreteCount), " +
    "Thunderbolt: $($thunderboltResults.Count), " +
    "EDID: $($edidMonitors.Count)."

Write-Host "`n$reportSummary"

# Export results if requested
if ($ExportResults) {
    Write-Host "`nExporting results..." -ForegroundColor Cyan
    $scanResults = [PSCustomObject]@{
        FinalColor = $resultColor
        DefiniteItems = $totalConcrete
        SuspiciousItems = $totalSuspicious
        SecureBoot = $secureBootText
        KernelDMA = $kernelDmaText
        PresentDevices = $presentDevices
        HiddenDevices = $hiddenDevices
        RegistryDevices = $registryDevices
        SetupAPISuspicious = $setupLogInfo.SuspiciousCount
        SetupAPIConcrete = $setupLogInfo.ConcreteCount
        SetupAPISuspiciousLines = $setupLogInfo.SuspiciousLines
        SetupAPIConcreteLines = $setupLogInfo.ConcreteLines
        ThunderboltEvents = $thunderboltResults
        EDIDMonitors = $edidMonitors
    }
    
    Export-ResultsToJSON -ScanResults $scanResults -FilePath $ExportPath
    Export-ResultsToHTML -ScanResults $scanResults -FilePath $ExportPath
    Export-ResultsToTXT -ScanResults $scanResults -FilePath $ExportPath
}

# Post to Discord if webhook provided (only sends clean summary, no progress messages)
if ($webhookUrl) {
    Write-Host "`nPosting results to Discord webhook..." -ForegroundColor Cyan
    $payload = @{
        content = $reportSummary
    }
    if ($webhookName) {
        $payload.username = $webhookName
    }
    try {
        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body ($payload | ConvertTo-Json) -ContentType 'application/json' -ErrorAction Stop
        Write-Host "Results posted to Discord webhook successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to post results to Discord webhook: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Troubleshooting: Verify the webhook URL is correct and the Discord server allows webhook posts." -ForegroundColor Yellow
    }
} else {
    Write-Host "`nNo webhook provided. Skipping Discord posting." -ForegroundColor Yellow
}

Write-Host "`nScan complete. Press Enter to exit..."
try {
    $null = Read-Host
} catch {
    Start-Sleep -Seconds 3
}

#endregion
