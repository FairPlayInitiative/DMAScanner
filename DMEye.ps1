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

Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host " DMEye {Pretournament System Checker} v1.1.0" -ForegroundColor Yellow
Write-Host " (c) 2018 EreVeX / DMEye System Checker" -ForegroundColor Gray
Write-Host "==================================================`n" -ForegroundColor Cyan
Write-Host "===== DMA DETECTION SCRIPT =====" -ForegroundColor Cyan

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
        # Enhanced input validation - accepts discord.com, discordapp.com, and discordapi.com
        $webhookUrl = $webhookUrl.Trim()
        if ($webhookUrl -notmatch "^https://(discord\.com|discordapp\.com|discordapi\.com)/api/webhooks/[\w/-]+$") {
            Write-Host "Invalid webhook URL format. Expected: https://discord.com/api/webhooks/... or https://discordapp.com/api/webhooks/... or https://discordapi.com/api/webhooks/..." -ForegroundColor Yellow
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


function Get-VBSStatus {
    # Checks Virtualization-based Security (VBS) status
    # Returns: $true if enabled, $false if disabled, $null if unsupported
    try {
        # Method 1: Check registry
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
        if (Test-Path $regPath) {
            $vbsValue = Get-ItemProperty -Path $regPath -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
            if ($null -ne $vbsValue -and $null -ne $vbsValue.EnableVirtualizationBasedSecurity) {
                if ($vbsValue.EnableVirtualizationBasedSecurity -eq 1) {
                    return $true
                } elseif ($vbsValue.EnableVirtualizationBasedSecurity -eq 0) {
                    return $false
                }
            }
        }
        
        # Method 2: Check via WMI/CIM (DeviceGuard namespace)
        try {
            $deviceGuard = Get-CimInstanceCompat -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard"
            if ($deviceGuard) {
                $vbsStatus = $deviceGuard | Select-Object -ExpandProperty VirtualizationBasedSecurityStatus -ErrorAction SilentlyContinue
                # Status values: 0=Off, 1=On, 2=On with UEFI lock
                if ($vbsStatus -eq 1 -or $vbsStatus -eq 2) {
                    return $true
                } elseif ($vbsStatus -eq 0) {
                    return $false
                }
            }
        } catch {
            # DeviceGuard namespace may not exist - expected on older systems
        }
        
        # Method 3: Check System Information
        $tempFile = $null
        try {
            if (-not (Get-Command "msinfo32.exe" -ErrorAction SilentlyContinue)) {
                return $null
            }
            
            $tempFile = "$env:TEMP\msinfo_vbs_$(Get-Random).txt"
            $null = Start-Process -FilePath "msinfo32.exe" -ArgumentList "/report", "`"$tempFile`"" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
            
            $maxWait = 15
            $waited = 0
            while (-not (Test-Path $tempFile) -and $waited -lt $maxWait) {
                Start-Sleep -Milliseconds 500
                $waited++
            }
            
            if (Test-Path $tempFile) {
                Start-Sleep -Milliseconds 1500
                $content = Get-Content $tempFile -ErrorAction SilentlyContinue
                if ($content) {
                    foreach ($line in $content) {
                        if ([string]::IsNullOrWhiteSpace($line)) { continue }
                        if ($line -match "Virtualization-based security\s*:\s*(\S+)") {
                            $result = $matches[1].Trim()
                            if ($result -eq "Enabled" -or $result -eq "Running") {
                                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                                return $true
                            }
                            if ($result -eq "Disabled" -or $result -eq "Not running") {
                                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                                return $false
                            }
                        }
                    }
                }
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        } catch {
            if ($tempFile -and (Test-Path $tempFile)) {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
        
    } catch {
        Write-Warning "Error checking VBS status: $($_.Exception.Message). Try running as Administrator."
    }
    
    return $null
}

function Get-TPMStatus {
    # Checks TPM (Trusted Platform Module) presence and status
    # Returns: @{Present=$true/$false; Version="2.0"/"1.2"/$null; Enabled=$true/$false/$null}
    $result = @{
        Present = $false
        Version = $null
        Enabled = $false
    }
    
    try {
        # Method 1: Check via TPM WMI provider
        $tpm = Get-CimInstanceCompat -Namespace "root\cimv2\security\microsofttpm" -ClassName "Win32_Tpm"
        if ($tpm) {
            $result.Present = $true
            $result.Enabled = $tpm.IsEnabled_InitialValue
            $result.Version = $tpm.SpecVersion
            return $result
        }
        
        # Method 2: Check via TPM PowerShell cmdlets (Windows 10+)
        if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
            $tpmInfo = Get-Tpm -ErrorAction SilentlyContinue
            if ($tpmInfo) {
                $result.Present = $tpmInfo.TpmPresent
                $result.Enabled = $tpmInfo.TpmEnabled
                $result.Version = if ($tpmInfo.TpmVersion) { $tpmInfo.TpmVersion } else { $null }
                return $result
            }
        }
        
        # Method 3: Check registry
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TPM"
        if (Test-Path $regPath) {
            $result.Present = $true
            # Can't determine version/enabled status from registry alone
        }
        
        # Method 4: Check System Information
        $tempFile = $null
        try {
            if (-not (Get-Command "msinfo32.exe" -ErrorAction SilentlyContinue)) {
                return $result
            }
            
            $tempFile = "$env:TEMP\msinfo_tpm_$(Get-Random).txt"
            $null = Start-Process -FilePath "msinfo32.exe" -ArgumentList "/report", "`"$tempFile`"" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
            
            $maxWait = 15
            $waited = 0
            while (-not (Test-Path $tempFile) -and $waited -lt $maxWait) {
                Start-Sleep -Milliseconds 500
                $waited++
            }
            
            if (Test-Path $tempFile) {
                Start-Sleep -Milliseconds 1500
                $content = Get-Content $tempFile -ErrorAction SilentlyContinue
                if ($content) {
                    foreach ($line in $content) {
                        if ([string]::IsNullOrWhiteSpace($line)) { continue }
                        if ($line -match "TPM\s+Version\s*:\s*(\S+)") {
                            $result.Present = $true
                            $result.Version = $matches[1].Trim()
                        }
                        if ($line -match "TPM\s+Manufacturer\s*:\s*(\S+)") {
                            $result.Present = $true
                        }
                    }
                }
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        } catch {
            if ($tempFile -and (Test-Path $tempFile)) {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
        
    } catch {
        Write-Warning "Error checking TPM status: $($_.Exception.Message)"
    }
    
    return $result
}


function Get-PreBootDMAProtection {
    # Attempts to check Pre-boot DMA Protection status
    # This is difficult to check from OS level, but we can infer from other settings
    # Returns: $true if likely enabled, $false if likely disabled, $null if unknown
    try {
        # Pre-boot DMA protection is typically tied to:
        # 1. Secure Boot being enabled
        # 2. Kernel DMA Protection being enabled
        # 3. UEFI firmware settings (not directly accessible from OS)
        # 4. TPM 2.0 presence
        # 5. IOMMU being enabled
        
        $secureBoot = Get-SecureBootStatus
        $tpmStatus = Get-TPMStatus
        
        # Method 1: Strong indicators - if Secure Boot and TPM are enabled, pre-boot protection is likely enabled
        if ($secureBoot -and $tpmStatus.Present -and $tpmStatus.Enabled) {
            # Critical components enabled - pre-boot protection is likely enabled
            return $true
        }
        
        # Method 2: Check registry for pre-boot DMA protection settings
        try {
            $preBootPaths = @(
                "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelDmaProtection",
                "HKLM:\SYSTEM\CurrentControlSet\Control\Firmware"
            )
            
            foreach ($path in $preBootPaths) {
                if (Test-Path $path) {
                    $preBootValue = Get-ItemProperty -Path $path -Name "PreBootDmaProtection" -ErrorAction SilentlyContinue
                    if ($null -ne $preBootValue -and $null -ne $preBootValue.PreBootDmaProtection) {
                        if ($preBootValue.PreBootDmaProtection -eq 1) {
                            return $true
                        }
                        if ($preBootValue.PreBootDmaProtection -eq 0) {
                            return $false
                        }
                    }
                    
                    # Check for related settings
                    $allProps = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                    if ($allProps) {
                        $preBootProps = $allProps.PSObject.Properties | Where-Object { 
                            $_.Name -match "Pre.*Boot|PreBoot|Boot.*DMA|DMA.*Boot" 
                        }
                        if ($preBootProps) {
                            foreach ($prop in $preBootProps) {
                                $val = $prop.Value
                                if ($val -eq 1 -or $val -match "Enabled|On|True") {
                                    return $true
                                }
                                if ($val -eq 0 -or $val -match "Disabled|Off|False") {
                                    return $false
                                }
                            }
                        }
                    }
                }
            }
        } catch {
            # Registry check failed - continue to other methods
        }
        
        # Method 3: Check System Information for pre-boot DMA protection
        $tempFile = $null
        try {
            if (Get-Command "msinfo32.exe" -ErrorAction SilentlyContinue) {
                $tempFile = "$env:TEMP\msinfo_preboot_$(Get-Random).txt"
                $null = Start-Process -FilePath "msinfo32.exe" -ArgumentList "/report", "`"$tempFile`"" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
                
                $maxWait = 15
                $waited = 0
                while (-not (Test-Path $tempFile) -and $waited -lt $maxWait) {
                    Start-Sleep -Milliseconds 500
                    $waited++
                }
                
                if (Test-Path $tempFile) {
                    Start-Sleep -Milliseconds 2000
                    $content = Get-Content $tempFile -ErrorAction SilentlyContinue
                    if ($content) {
                        foreach ($line in $content) {
                            if ([string]::IsNullOrWhiteSpace($line)) { continue }
                            if ($line -match "Pre.*Boot.*DMA|PreBoot.*DMA|Boot.*DMA.*Protection" -and 
                                $line -match "(Enabled|On|Yes|Active)") {
                                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                                return $true
                            }
                            if ($line -match "Pre.*Boot.*DMA|PreBoot.*DMA|Boot.*DMA.*Protection" -and 
                                $line -match "(Disabled|Off|No|Inactive)") {
                                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                                return $false
                            }
                        }
                    }
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            if ($tempFile -and (Test-Path $tempFile)) {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Method 4: Inference based on component status
        # If Secure Boot is disabled, Pre-boot DMA Protection is very likely disabled
        if (-not $secureBoot) {
            return $false
        }
        
        # If Secure Boot is enabled, check TPM status
        if ($secureBoot) {
            # Secure Boot enabled - check if TPM is present (often required)
            if ($tpmStatus.Present -and $tpmStatus.Enabled) {
                return $true
            }
            # Secure Boot enabled but TPM not present/disabled - might still work but less certain
            return $null
        }
        
        # Otherwise, we can't determine with certainty
        return $null
        
    } catch {
        # Error occurred - return null
    }
    
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
    $foundDevices = @()
    
    try {
        $deviceList = Get-CimInstanceCompat -ClassName "Win32_PnPEntity"
        if ($null -eq $deviceList) {
            return $foundDevices
        }
        
        # Handle both single object and array
        if ($deviceList -is [array]) {
            $totalDevices = $deviceList.Count
        } else {
            $deviceList = @($deviceList)
            $totalDevices = 1
        }
        
        $processed = 0
        foreach ($device in $deviceList) {
            $processed++
            if ($totalDevices -gt 0 -and $processed % 50 -eq 0) {
                $percentComplete = 10 + [Math]::Min(20, ($processed / $totalDevices * 20))
                Write-ProgressStep -Activity "Scanning Devices" -Status "Processing device $processed of $totalDevices..." -PercentComplete $percentComplete
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
    } catch {
        Write-Warning "Error scanning present PCI devices: $($_.Exception.Message)"
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
    
    try {
        $allDevices = Get-PnpDevice -PresentOnly:$false -ErrorAction SilentlyContinue
        if ($null -eq $allDevices) {
            return @()
        }
        
        $hiddenResults = @()
        $totalDevices = ($allDevices | Where-Object { $_.Status -eq "Unknown" -or $_.Status -eq "Error" }).Count
        $processed = 0
        
        foreach ($device in $allDevices) {
            if ($device.Status -eq "Unknown" -or $device.Status -eq "Error") {
                $processed++
                if ($totalDevices -gt 0 -and $processed % 10 -eq 0) {
                    $percentComplete = 35 + [Math]::Min(15, ($processed / $totalDevices * 15))
                    Write-ProgressStep -Activity "Scanning Devices" -Status "Processing hidden device $processed of $totalDevices..." -PercentComplete $percentComplete
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
    } catch {
        Write-Warning "Error scanning hidden devices: $($_.Exception.Message)"
        return @()
    }
    return $hiddenResults
}

function Get-SuspiciousRegistryPCIDevices {
    Write-ProgressStep -Activity "Scanning Devices" -Status "Checking registry PCI entries..." -PercentComplete 55
    Write-Host "   [Scanning] Checking registry PCI entries..." -ForegroundColor Gray
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"
    $registryResults = @()
    
    if (Test-Path $registryPath) {
        try {
            $registryItems = Get-ChildItem $registryPath -ErrorAction SilentlyContinue
            if ($null -eq $registryItems) {
                return $registryResults
            }
            
            # Handle both single object and array
            if ($registryItems -is [array]) {
                $totalItems = $registryItems.Count
            } else {
                $registryItems = @($registryItems)
                $totalItems = 1
            }
            
            $processed = 0
            foreach ($item in $registryItems) {
                $processed++
                if ($totalItems -gt 0 -and $processed % 100 -eq 0) {
                    $percentComplete = 55 + [Math]::Min(10, ($processed / $totalItems * 10))
                    Write-ProgressStep -Activity "Scanning Devices" -Status "Processing registry entry $processed of $totalItems..." -PercentComplete $percentComplete
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
        } catch {
            Write-Warning "Error scanning registry: $($_.Exception.Message)"
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
                    if ($totalLines -gt 0 -and $lineNumber % 5000 -eq 0) {
                        $percent = 70 + [Math]::Min(20, ($lineNumber / $totalLines * 20))
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
            foreach ($evt in $events) {
                if ($evt.Message -match "(unauthorized|failed|blocked)") {
                    $thunderboltEvents += [PSCustomObject]@{
                        Event = $evt
                        TimeCreated = $evt.TimeCreated
                        Id = $evt.Id
                        Message = $evt.Message
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
            CoreIsolation = $ScanResults.CoreIsolation
            TamperProtection = $ScanResults.TamperProtection
            DefenderRealTime = $ScanResults.DefenderRealTime
            VBS = $ScanResults.VBS
            TPM = $ScanResults.TPM
            PreBootDMA = $ScanResults.PreBootDMA
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
        <p>Core Isolation (HVCI): $($ScanResults.CoreIsolation)</p>
        <p>Tamper Protection: $($ScanResults.TamperProtection)</p>
        <p>Defender Real-Time: $($ScanResults.DefenderRealTime)</p>
        <p>VBS: $($ScanResults.VBS)</p>
        <p>TPM: $($ScanResults.TPM)</p>
        <p>Pre-boot DMA Protection: $($ScanResults.PreBootDMA)</p>
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
Core Isolation (HVCI): $($ScanResults.CoreIsolation)
Tamper Protection: $($ScanResults.TamperProtection)
Defender Real-Time: $($ScanResults.DefenderRealTime)
VBS: $($ScanResults.VBS)
TPM: $($ScanResults.TPM)
Pre-boot DMA Protection: $($ScanResults.PreBootDMA)

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

# Initialize variables to prevent errors
$secureBootText = "UNKNOWN"
$coreIsolationText = "UNKNOWN"
$tamperProtectionText = "UNKNOWN"
$defenderRealTimeText = "UNKNOWN"
$diagTrackStatusText = "UNKNOWN"
$sysMainStatusText = "UNKNOWN"
$vbsText = "UNSUPPORTED"
$tpmVersionText = "NOT PRESENT"
$tpmEnabledText = "N/A"
$preBootDMAText = "UNKNOWN"

try {
    Write-Host "\n================[ SYSTEM SECURITY CHECKS ]================" -ForegroundColor Magenta
    $secureBootEnabled = Get-SecureBootStatus
    $coreIsolationStatus = Get-CoreIsolationStatus
    $tamperProtectionStatus = Get-TamperProtectionStatus
    $defenderRealTimeStatus = Get-DefenderRealTimeStatus

    # Additional service checks
    try {
        $diagTrackService = Get-Service -Name 'DiagTrack' -ErrorAction SilentlyContinue
        if ($null -ne $diagTrackService) {
            $diagTrackStatusText = if ($diagTrackService.Status -eq 'Running') { 'ENABLED' } else { 'DISABLED' }
        } else {
            $diagTrackStatusText = 'NOT INSTALLED'
        }
    } catch {
        $diagTrackStatusText = 'UNKNOWN'
    }
    
    try {
        $sysMainService = Get-Service -Name 'SysMain' -ErrorAction SilentlyContinue
        if ($null -ne $sysMainService) {
            $sysMainStatusText = if ($sysMainService.Status -eq 'Running') { 'ENABLED' } else { 'DISABLED' }
        } else {
            $sysMainStatusText = 'NOT INSTALLED'
        }
    } catch {
        $sysMainStatusText = 'UNKNOWN'
    }

$secureBootText = if ($secureBootEnabled) { "ENABLED" } else { "DISABLED" }

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

# Additional DMA-specific security checks
Write-Host "\n================[ ADVANCED DMA & VIRTUALIZATION CHECKS ]================" -ForegroundColor Magenta

# Check VBS status
$vbsStatus = Get-VBSStatus
if ($vbsStatus -eq $true) {
    $vbsText = "ENABLED"
    Write-Host " - Virtualization-based Security (VBS): ENABLED" -ForegroundColor Green
} elseif ($vbsStatus -eq $false) {
    $vbsText = "DISABLED"
    Write-Host " - Virtualization-based Security (VBS): DISABLED" -ForegroundColor Yellow
} else {
    $vbsText = "UNSUPPORTED"
    Write-Host " - Virtualization-based Security (VBS): UNSUPPORTED" -ForegroundColor Yellow
}

# Check TPM status
$tpmStatus = Get-TPMStatus
if ($tpmStatus.Present) {
    $tpmVersionText = if ($tpmStatus.Version) { "TPM $($tpmStatus.Version)" } else { "TPM (version unknown)" }
    $tpmEnabledText = if ($tpmStatus.Enabled) { "ENABLED" } else { "DISABLED" }
    Write-Host " - TPM: PRESENT ($tpmVersionText, $tpmEnabledText)" -ForegroundColor $(if ($tpmStatus.Enabled -and $tpmStatus.Version -match "2\.0") { "Green" } else { "Yellow" })
} else {
    $tpmVersionText = "NOT PRESENT"
    $tpmEnabledText = "N/A"
    Write-Host " - TPM: NOT PRESENT" -ForegroundColor Yellow
}

# Check Pre-boot DMA Protection
$preBootDMA = Get-PreBootDMAProtection
if ($preBootDMA -eq $true) {
    $preBootDMAText = "LIKELY ENABLED"
    Write-Host " - Pre-boot DMA Protection: LIKELY ENABLED" -ForegroundColor Green
} elseif ($preBootDMA -eq $false) {
    $preBootDMAText = "LIKELY DISABLED"
    Write-Host " - Pre-boot DMA Protection: LIKELY DISABLED" -ForegroundColor Yellow
} else {
    $preBootDMAText = "UNKNOWN"
    Write-Host " - Pre-boot DMA Protection: UNKNOWN (requires BIOS check)" -ForegroundColor Yellow
}

Write-Host "\n================[ DEVICE ENUMERATION & EVENT LOGS ]================" -ForegroundColor Magenta

# Initialize device arrays to prevent errors
$presentDevices = @()
$hiddenDevices = @()
$registryDevices = @()
$concretePresent = @()
$suspiciousPresent = @()
$concreteHidden = @()
$suspiciousHidden = @()
$setupLogInfo = [PSCustomObject]@{ SuspiciousCount = 0; ConcreteCount = 0; SuspiciousLines = @(); ConcreteLines = @() }
$thunderboltResults = @()
$edidMonitors = @()

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
    if ($null -eq $thunderboltResults) {
        $thunderboltResults = @()
    }
    Write-Host " - Thunderbolt events: $($thunderboltResults.Count) unauthorized/blocked."
    
    if ($thunderboltResults.Count -gt 0) {
        Write-Host "`n   Thunderbolt Event Details:" -ForegroundColor Cyan
        foreach ($evt in $thunderboltResults) {
            Write-Host "     Event ID: $($evt.Id) - $($evt.TimeCreated)" -ForegroundColor Yellow
            if ($evt.Message) {
                $msgLength = [Math]::Min(100, $evt.Message.Length)
                Write-Host "       $($evt.Message.Substring(0, $msgLength))" -ForegroundColor Gray
            }
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
    if ($null -eq $edidMonitors) {
        $edidMonitors = @()
    }
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
if ($null -ne $suspiciousPresent) { $totalSuspicious += $suspiciousPresent.Count }
if ($null -ne $concretePresent) { $totalConcrete += $concretePresent.Count }
if ($null -ne $suspiciousHidden) { $totalSuspicious += $suspiciousHidden.Count }
if ($null -ne $concreteHidden) { $totalConcrete += $concreteHidden.Count }
if ($null -ne $registryDevices) { $totalSuspicious += $registryDevices.Count }
if ($null -ne $setupLogInfo) {
    $totalSuspicious += $setupLogInfo.SuspiciousCount
    $totalConcrete += $setupLogInfo.ConcreteCount
}
if ($null -ne $thunderboltResults -and $thunderboltResults.Count -gt 0) { $totalSuspicious++ }
if ($null -ne $edidMonitors -and $edidMonitors.Count -gt 1) { $totalSuspicious++ }

Write-Host "\n================[ SCAN SUMMARY & FINAL RESULT ]================" -ForegroundColor Magenta
$resultColor = "Green"
if ($totalConcrete -gt 0) {
    $resultColor = "Red"
} elseif ($totalSuspicious -gt 0) {
    $resultColor = "Yellow"
}

Write-Host "\n==================================================" -ForegroundColor Cyan
Write-Host ("{0,-28} {1,-10}" -f 'Category', 'Status') -ForegroundColor Yellow
Write-Host ("{0,-28} {1,-10}" -f '--------------------------', '----------') -ForegroundColor Yellow

# Color-coded summary table
Write-Host "`nSummary Table:" -ForegroundColor Cyan
$summaryTable = @(
    [PSCustomObject]@{ Category = "Final Result"; Value = $resultColor; Status = $resultColor }
    [PSCustomObject]@{ Category = "Definite Items"; Value = $totalConcrete; Status = if ($totalConcrete -gt 0) { "Red" } else { "Green" } }
    [PSCustomObject]@{ Category = "Suspicious Items"; Value = $totalSuspicious; Status = if ($totalSuspicious -gt 0) { "Yellow" } else { "Green" } }
    [PSCustomObject]@{ Category = "Secure Boot"; Value = $secureBootText; Status = if ($secureBootEnabled) { "Green" } else { "Yellow" } }
    [PSCustomObject]@{ Category = "Core Isolation (HVCI)"; Value = $coreIsolationText; Status = if ($coreIsolationStatus -eq $true) { "Green" } elseif ($coreIsolationStatus -eq $false) { "Yellow" } else { "Yellow" } }
    [PSCustomObject]@{ Category = "Tamper Protection"; Value = $tamperProtectionText; Status = if ($tamperProtectionStatus -eq $true) { "Green" } elseif ($tamperProtectionStatus -eq $false) { "Yellow" } else { "Yellow" } }
    [PSCustomObject]@{ Category = "Defender Real-Time"; Value = $defenderRealTimeText; Status = if ($defenderRealTimeStatus -eq $true) { "Green" } elseif ($defenderRealTimeStatus -eq $false) { "Yellow" } else { "Yellow" } }
    [PSCustomObject]@{ Category = "VBS"; Value = $vbsText; Status = if ($vbsStatus -eq $true) { "Green" } elseif ($vbsStatus -eq $false) { "Yellow" } else { "Yellow" } }
    [PSCustomObject]@{ Category = "TPM"; Value = if ($null -ne $tpmStatus -and $tpmStatus.Present) { "$tpmVersionText ($tpmEnabledText)" } else { "NOT PRESENT" }; Status = if ($null -ne $tpmStatus -and $tpmStatus.Present -and $tpmStatus.Enabled -and $tpmStatus.Version -match "2\.0") { "Green" } elseif ($null -ne $tpmStatus -and $tpmStatus.Present) { "Yellow" } else { "Yellow" } }
    [PSCustomObject]@{ Category = "Pre-boot DMA"; Value = $preBootDMAText; Status = if ($preBootDMA -eq $true) { "Green" } elseif ($preBootDMA -eq $false) { "Yellow" } else { "Yellow" } }
    [PSCustomObject]@{ Category = "Present PCI"; Value = if ($null -ne $presentDevices) { $presentDevices.Count } else { 0 }; Status = if ($null -ne $presentDevices -and $presentDevices.Count -gt 0) { "Yellow" } else { "Green" } }
    [PSCustomObject]@{ Category = "Hidden PCI"; Value = if ($null -ne $hiddenDevices) { $hiddenDevices.Count } else { 0 }; Status = if ($null -ne $hiddenDevices -and $hiddenDevices.Count -gt 0) { "Yellow" } else { "Green" } }
    [PSCustomObject]@{ Category = "Registry PCI"; Value = if ($null -ne $registryDevices) { $registryDevices.Count } else { 0 }; Status = if ($null -ne $registryDevices -and $registryDevices.Count -gt 0) { "Yellow" } else { "Green" } }
    [PSCustomObject]@{ Category = "SetupAPI Lines"; Value = if ($null -ne $setupLogInfo) { ($setupLogInfo.SuspiciousCount + $setupLogInfo.ConcreteCount) } else { 0 }; Status = if ($null -ne $setupLogInfo -and (($setupLogInfo.SuspiciousCount + $setupLogInfo.ConcreteCount) -gt 0)) { "Yellow" } else { "Green" } }
    [PSCustomObject]@{ Category = "Thunderbolt Events"; Value = if ($null -ne $thunderboltResults) { $thunderboltResults.Count } else { 0 }; Status = if ($null -ne $thunderboltResults -and $thunderboltResults.Count -gt 0) { "Yellow" } else { "Green" } }
    [PSCustomObject]@{ Category = "EDID Monitors"; Value = if ($null -ne $edidMonitors) { $edidMonitors.Count } else { 0 }; Status = if ($null -ne $edidMonitors -and $edidMonitors.Count -gt 1) { "Yellow" } else { "Green" } }
)

foreach ($row in $summaryTable) {
    $color = switch ($row.Status) {
        "Red" { "Red" }
        "Yellow" { "Yellow" }
        default { "Green" }
    }
    $icon = switch ($row.Status) {
        "Red" { "✗" }
        "Yellow" { "!" }
        default { "✓" }
    }
    Write-Host (" {0,-2} {1,-25} {2}" -f $icon, $row.Category, $row.Value) -ForegroundColor $color
}

switch ($resultColor) {
    "Red" {
        if ($totalConcrete -gt 0) {
            Write-Host "`nRED: 100% EVIDENCE OF DMA CHEAT DETECTED!" -ForegroundColor Red
        } else {
            Write-Host "`nRED: Suspicious devices found - Definite DMA threat detected." -ForegroundColor Red
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
    "Core Isolation (HVCI): $coreIsolationText`n" +
    "Tamper Protection: $tamperProtectionText`n" +
    "Defender Real-Time: $defenderRealTimeText`n" +
    "VBS: $vbsText`n" +
    "TPM: $(if ($null -ne $tpmStatus -and $tpmStatus.Present) { "$tpmVersionText ($tpmEnabledText)" } else { "NOT PRESENT" })`n" +
    "Pre-boot DMA Protection: $preBootDMAText`n" +
    "Connected User Experiences & Telemetry (DiagTrack): $diagTrackStatusText`n" +
    "SysMain: $sysMainStatusText`n" +
    "`nScan Results:`n" +
    "Present PCI suspicious: $(if ($null -ne $presentDevices) { $presentDevices.Count } else { 0 }), " +
    "Hidden PCI suspicious: $(if ($null -ne $hiddenDevices) { $hiddenDevices.Count } else { 0 }), " +
    "Registry suspicious: $(if ($null -ne $registryDevices) { $registryDevices.Count } else { 0 }), " +
    "SetupAPI suspicious lines: $(if ($null -ne $setupLogInfo) { ($setupLogInfo.SuspiciousCount + $setupLogInfo.ConcreteCount) } else { 0 }), " +
    "Thunderbolt: $(if ($null -ne $thunderboltResults) { $thunderboltResults.Count } else { 0 }), " +
    "EDID: $(if ($null -ne $edidMonitors) { $edidMonitors.Count } else { 0 })."

Write-Host "`n$reportSummary"

# Export results if requested
if ($ExportResults) {
    Write-Host "`nExporting results..." -ForegroundColor Cyan
    $scanResults = [PSCustomObject]@{
        FinalColor = $resultColor
        DefiniteItems = $totalConcrete
        SuspiciousItems = $totalSuspicious
        SecureBoot = $secureBootText
        CoreIsolation = $coreIsolationText
        TamperProtection = $tamperProtectionText
        DefenderRealTime = $defenderRealTimeText
        VBS = $vbsText
        TPM = if ($null -ne $tpmStatus -and $tpmStatus.Present) { "$tpmVersionText ($tpmEnabledText)" } else { "NOT PRESENT" }
        PreBootDMA = $preBootDMAText
        PresentDevices = if ($null -ne $presentDevices) { $presentDevices } else { @() }
        HiddenDevices = if ($null -ne $hiddenDevices) { $hiddenDevices } else { @() }
        RegistryDevices = if ($null -ne $registryDevices) { $registryDevices } else { @() }
        SetupAPISuspicious = if ($null -ne $setupLogInfo) { $setupLogInfo.SuspiciousCount } else { 0 }
        SetupAPIConcrete = if ($null -ne $setupLogInfo) { $setupLogInfo.ConcreteCount } else { 0 }
        SetupAPISuspiciousLines = if ($null -ne $setupLogInfo) { $setupLogInfo.SuspiciousLines } else { @() }
        SetupAPIConcreteLines = if ($null -ne $setupLogInfo) { $setupLogInfo.ConcreteLines } else { @() }
        ThunderboltEvents = if ($null -ne $thunderboltResults) { $thunderboltResults } else { @() }
        EDIDMonitors = if ($null -ne $edidMonitors) { $edidMonitors } else { @() }
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

} catch {
    Write-Host "`nFATAL ERROR: An unexpected error occurred during execution." -ForegroundColor Red
    Write-Host "Error Details: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Yellow
    Write-Host "`nPlease report this error with the details above." -ForegroundColor Yellow
    Write-Host "`nPress Enter to exit..."
    try {
        $null = Read-Host
    } catch {
        Start-Sleep -Seconds 3
    }
}

#endregion
