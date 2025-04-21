# special statement
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess=$true)] # Added for -WhatIf support
param(
    # check for updates on github
    [switch]$CheckForUpdate,
    # current version
    [switch]$Version
)

# --- Script Version and Repo Information ---
$CurrentVersion = '1.0.0'
$RepoOwner = 'mirbyte'
$RepoName = 'Phone-Link-Uninstaller'
# $PowerShellGalleryName = 'YourScriptNameOnPSGallery'

# --- Display Version ---
if ($Version.IsPresent) {
    Write-Host $CurrentVersion
    exit 0
}


# UPDATE CHECK IS NOT PROPERLY IMPLEMENTED YET!
# --- Update Check Functions START ---
# (Adapted from https://github.com/asheroto/UninstallOneDrive & https://github.com/asheroto/UninstallTeams)
function Get-GitHubRelease {
    [CmdletBinding()]
    param (
        [string]$Owner,
        [string]$Repo
    )
    try {
        $url = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
        # Use System.Net.WebClient for potentially better compatibility than Invoke-RestMethod on older PS versions
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell Script")
        $responseJson = $webClient.DownloadString($url)
        $response = ConvertFrom-Json -InputObject $responseJson -ErrorAction Stop

        $latestVersion = $response.tag_name -replace '^v','' # Remove leading 'v' if present
        $publishedAt = $response.published_at
        $UtcDateTime = [DateTime]::Parse($publishedAt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $PublishedLocalDateTime = $UtcDateTime.ToLocalTime()

        [PSCustomObject]@{
            LatestVersion     = $latestVersion
            PublishedDateTime = $PublishedLocalDateTime
        }
    } catch {
        Write-Warning "Unable to check for updates. Error: $($_.Exception.Message)"
        return $null
    }
}

function CheckForUpdate {
    param (
        [string]$RepoOwner,
        [string]$RepoName,
        [version]$CurrentVersion
        # Optional: Add PowerShell Gallery Name parameter if implementing UpdateSelf
        # [string]$PowerShellGalleryName
    )

    Write-Host "Checking for updates..."
    $Data = Get-GitHubRelease -Owner $RepoOwner -Repo $RepoName

    if (-not $Data) {
        Write-Warning "Could not retrieve update information."
        exit 1
    }

    Write-Host "`nRepository:       https://github.com/$RepoOwner/$RepoName"
    Write-Host "Current Version:  $CurrentVersion"
    Write-Host "Latest Version:   $($Data.LatestVersion)"
    Write-Host "Published at:     $($Data.PublishedDateTime)"

    try {
        $latestVersionObject = [version]$Data.LatestVersion
        if ($latestVersionObject -gt $CurrentVersion) {
            Write-Host "Status:           A new version is available." -ForegroundColor Yellow
            Write-Host "`nDownload latest release: https://github.com/$RepoOwner/$RepoName/releases"
            # Optional: Add UpdateSelf instructions if implemented
            # if ($PowerShellGalleryName) {
            #     Write-Host "- Run: $RepoName -UpdateSelf"
            #     Write-Host "- Run: Install-Script $PowerShellGalleryName -Force"
            # }
        } elseif ($latestVersionObject -eq $CurrentVersion) {
            Write-Host "Status:           You are using the latest version." -ForegroundColor Green
        } else {
            # Should not happen often, but handle case where current > latest
             Write-Host "Status:           Your version ($CurrentVersion) is newer than the latest release ($($Data.LatestVersion))." -ForegroundColor Cyan
        }
    } catch {
         Write-Warning "Could not compare versions. Latest version reported as '$($Data.LatestVersion)'. Error: $($_.Exception.Message)"
    }
    exit 0
}


if ($CheckForUpdate) {
    CheckForUpdate -RepoOwner $RepoOwner -RepoName $RepoName -CurrentVersion ([version]$CurrentVersion) # Pass PowerShellGalleryName if needed
}
# --- Update Check Functions END ---



# --- Initial Setup ---
# $Host.UI.RawUI.BackgroundColor = "DarkGray"
Clear-Host
$Host.UI.RawUI.WindowTitle = "Phone-Link-Uninstaller v$CurrentVersion (github/$RepoOwner)"

# --- Banner ---
Write-Host "================================================" -ForegroundColor Yellow
Write-Host "  Phone Link / PhoneExperienceHost Uninstaller " -ForegroundColor Yellow
Write-Host "                  Version $CurrentVersion                 " -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Yellow

# --- Setup Logging ---
$ScriptLogPath = $PSScriptRoot # Directory where the script is located
# Handle cases where $PSScriptRoot might be empty (e.g., running selection in ISE)
if (-not $ScriptLogPath) { $ScriptLogPath = Get-Location }

# Define and create the logs directory
$LogsDirectory = Join-Path -Path $ScriptLogPath -ChildPath "logs"
if (-not (Test-Path -Path $LogsDirectory -PathType Container)) {
    try {
        New-Item -Path $LogsDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning "Could not create logs directory '$LogsDirectory'. Logs will be saved in script directory. Error: $($_.Exception.Message)"
        $LogsDirectory = $ScriptLogPath # Fallback to script directory if creation fails
    }
}

# Define the log file path within the logs directory
$LogFile = Join-Path -Path $LogsDirectory -ChildPath ("PhoneLinkUninstallerLog_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
$TranscriptActive = $false
try {
    # Redirect host output for Start-Transcript to suppress default messages
    Start-Transcript -Path $LogFile -Append -Force -ErrorAction Stop *>$null
    $TranscriptActive = $true
} catch {
    Write-Warning "Could not start transcript logging to '$LogFile'. Error: $($_.Exception.Message)"
}

# --- Execution Policy Check ---
# Attempt to set Execution Policy for this process instance first
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
} catch {
    Write-Warning "Could not set execution policy for the current process. This might be due to Group Policy."
    Write-Warning "Attempting to continue. If the script fails, ensure PowerShell execution policy allows scripts."
}

# --- Admin Check ---
# The #Requires statement handles this, but we double-check for clarity and immediate exit.
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-Not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
     Write-Error "This script requires Administrator privileges. Please re-run PowerShell as Administrator."
     if ($Host.UI.RawUI -ne $null) { Read-Host -Prompt "Press Enter to exit" }
     # Ensure transcript stops before exiting
     if ($TranscriptActive) { try { Stop-Transcript -ErrorAction SilentlyContinue *>$null } catch {} }
     Exit 1 # Exit the script if not admin
} else {
    # Write-Host "Running with Administrator privileges..." # Keep output minimal
    if ($PSBoundParameters.ContainsKey('WhatIf') -and $PSBoundParameters['WhatIf']) {
         Write-Warning "Running in -WhatIf mode. No changes will be made."
    }
}


# --- Configuration ---
# Define patterns for AppX packages to remove. Wildcards (*) match any characters.
$AppPackagePatterns = @(
    "*Microsoft.YourPhone*",          # Original name pattern
    "*Microsoft.PhoneExperienceHost*",# Newer name pattern / Host process App
    "*Microsoft.Windows.PhoneLink*"  # Current official name pattern
    # "*Microsoft.PPIProjection*",      # Often related, keep if needed, commented out for focus
    # "*Microsoft.CommsPhone*"          # Related communication component, keep if needed, commented out for focus
)

# Use the same patterns for provisioned packages
$ProvisionedPackagePatterns = $AppPackagePatterns

# Define patterns for finding leftover FOLDERS in %LOCALAPPDATA%\Packages
$LeftoverFolderPatterns = @(
    "Microsoft.YourPhone_*",
    "Microsoft.PhoneExperienceHost_*",
    "Microsoft.Windows.PhoneLink_*"  # FIX: Removed trailing comma
    # "Microsoft.PPIProjection_*", # Keep if needed
    # "Microsoft.CommsPhone_*"     # Keep if needed
)

# SERVICE NAMES to stop. (Likely none needed for Phone Link, but kept for structure)
$ServicesToStop = @()

# Define specific SCHEDULED TASK names or path patterns to remove.
$ScheduledTaskPatterns = @(
    "*YourPhone*",
    "*PhoneExperienceHost*",
    "*Windows.PhoneLink*"
    # "*PPIProjection*" # needed??
)

# Define KNOWN REGISTRY KEYS or PATTERNS to remove (Pattern matching part).
$KnownLeftoverRegKeys = @(
   # Specific Keys (will be attempted by Remove-Item directly)
   "HKCU:\Software\Microsoft\YourPhone",
   "HKCU:\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociation\UrlAssociations\ms-yourphone",
   "HKCR:\ms-yourphone", # Protocol handler

   # Patterns (will be attempted by Get-Item/Remove-Item with wildcard)
   "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.YourPhone_*",
   "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.Windows.PhoneLink_*",
   "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_*",
   "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.PhoneLink_*",
   "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.YourPhone_*",
   "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.Windows.PhoneLink_*",
   "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\HostActivityManager\CommitHistory\Microsoft.YourPhone_*",
   "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\HostActivityManager\CommitHistory\Microsoft.Windows.PhoneLink_*"
   # Add more specific keys or patterns if discovered
)

# Define specific STARTUP registry value names/patterns to remove (Targeted removal)
$StartupValuePatternsToRemove = @(
    "*YourPhone*",
    "*PhoneExperienceHost*",
    "*Windows.PhoneLink*"
)


# --- Phase 0: Stop Related Services ---
Write-Host "`n--- Phase 0: Stopping Services ---" -ForegroundColor Cyan
$ServicesStoppedOrNotFound = $true
if ($ServicesToStop.Count -gt 0) {
    foreach ($serviceName in $ServicesToStop) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne 'Stopped') {
                if ($PSCmdlet.ShouldProcess($serviceName, "Stop Service")) {
                    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue # Re-check status
                    if ($service.Status -eq 'Stopped') {
                        Write-Host "   Service '$serviceName' stopped successfully." -ForegroundColor Green
                    } else {
                        Write-Warning "Service '$serviceName' could not be stopped (Current Status: $($service.Status))."
                        $ServicesStoppedOrNotFound = $false
                    }
                }
            } else {
                 # Write-Host "Service '$serviceName' is already stopped." -ForegroundColor DarkGray # Keep output minimal
            }
        } else {
            # Write-Host "Service '$serviceName' not found." -ForegroundColor DarkGray # Keep output minimal
        }
    }
} else {
     Write-Host "   No services configured to stop." -ForegroundColor DarkGray
}


# --- Phase 1: Uninstall AppX Packages (All Users) ---
Write-Host "`n--- Phase 1: Uninstalling AppX Packages ---" -ForegroundColor Cyan
$packagesRemovedCount = 0
foreach ($pattern in $AppPackagePatterns) {
    try {
        # Get packages matching the pattern for all users
        $packages = Get-AppxPackage -AllUsers -Name $pattern -ErrorAction SilentlyContinue
        if ($packages) {
            foreach ($package in $packages) {
                if ($PSCmdlet.ShouldProcess($package.PackageFullName, "Remove AppX Package")) {
                    try {
                        Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction Stop
                        Write-Host "   Removed AppX: $($package.Name)" -ForegroundColor Green
                        $packagesRemovedCount++
                    } catch {
                        Write-Error "ERROR removing AppX package '$($package.PackageFullName)': $($_.Exception.Message)"
                    }
                }
            }
        } else {
            # Write-Host "   No AppX packages found matching pattern '$pattern'." -ForegroundColor DarkGray # Keep output minimal
        }
    } catch {
         # This catch block might indicate a broader issue with Get-AppxPackage
         Write-Warning "   Error querying AppX packages for pattern '$pattern': $($_.Exception.Message)"
    }
}
if ($packagesRemovedCount -eq 0) {
    Write-Host "   No relevant AppX packages found or removed." -ForegroundColor DarkGray
} else {
    Write-Host "   Removed $packagesRemovedCount AppX package(s)." -ForegroundColor Green
}


# --- Phase 2: Remove Provisioned Packages ---
Write-Host "`n--- Phase 2: Removing Provisioned Packages ---" -ForegroundColor Cyan
$provisionedRemovedCount = 0
foreach ($pattern in $ProvisionedPackagePatterns) {
    try {
        # Get provisioned packages matching the pattern
        $provisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like $pattern } -ErrorAction SilentlyContinue
        if ($provisionedPackages) {
            foreach ($provPackage in $provisionedPackages) {
                 if ($PSCmdlet.ShouldProcess($provPackage.PackageName, "Remove Provisioned Package")) {
                    try {
                        Remove-AppxProvisionedPackage -Online -PackageName $provPackage.PackageName -ErrorAction Stop
                        Write-Host "   Removed Provisioned Package: $($provPackage.DisplayName)" -ForegroundColor Green
                        $provisionedRemovedCount++
                    } catch {
                        Write-Error "ERROR removing provisioned package '$($provPackage.PackageName)': $($_.Exception.Message)"
                    }
                }
            }
        } else {
             # Write-Host "   No provisioned packages found matching pattern '$pattern'." -ForegroundColor DarkGray # Keep output minimal
        }
    } catch {
         # This catch block might indicate a broader issue with Get-AppxProvisionedPackage
         Write-Warning "Error querying provisioned packages for pattern '$pattern': $($_.Exception.Message)"
    }
}
if ($provisionedRemovedCount -eq 0) {
    Write-Host "   No relevant provisioned packages found or removed." -ForegroundColor DarkGray
} else {
    Write-Host "   Removed $provisionedRemovedCount provisioned package(s)." -ForegroundColor Green
}


# --- Phase 3: Remove Scheduled Tasks ---
Write-Host "`n--- Phase 3: Removing Scheduled Tasks ---" -ForegroundColor Cyan
$tasksRemovedCount = 0
foreach ($pattern in $ScheduledTaskPatterns) {
    try {
        # Get scheduled tasks matching the pattern in name or path
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like $pattern -or $_.TaskPath -like "*$pattern*" } -ErrorAction SilentlyContinue
        if ($tasks) {
            foreach ($task in $tasks) {
                $taskIdentifier = "'$($task.TaskPath)$($task.TaskName)'"
                 if ($PSCmdlet.ShouldProcess($taskIdentifier, "Unregister Scheduled Task")) {
                    try {
                        Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                        Write-Host "   Unregistered task $taskIdentifier." -ForegroundColor Green
                        $tasksRemovedCount++
                    } catch {
                        Write-Error ("Failed to unregister task {0}: {1}" -f $taskIdentifier, $_.Exception.Message)
                    }
                }
            }
        } else {
            # Write-Host "   No scheduled tasks found matching pattern '$pattern'." -ForegroundColor DarkGray # Keep output minimal
        }
    } catch {
        # This catch block might indicate a broader issue with Get-ScheduledTask
        Write-Warning "Error searching for scheduled tasks matching '$pattern': $($_.Exception.Message)"
    }
}
if ($tasksRemovedCount -eq 0) {
    Write-Host "   No relevant scheduled tasks found or removed." -ForegroundColor DarkGray
} else {
    Write-Host "   Removed $tasksRemovedCount scheduled task(s)." -ForegroundColor Green
}


# --- Phase 4: Cleanup Leftover Filesystem/Registry ---
Write-Host "`n--- Phase 4: Known Leftover Locations ---" -ForegroundColor Cyan
$foldersCleanedCount = 0
$regKeysCleanedCount = 0
$startupValuesCleanedCount = 0

# 4a: Targeted Startup Registry Value Removal (Based on UninstallTeams approach)
$StartupRegPaths = @(
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', # Check WOW6432Node paths as well
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
# Write-Host "   Checking common startup locations..." -ForegroundColor DarkGray
foreach ($regPath in $StartupRegPaths) {
    # Check if path exists before trying to get properties
    if (Test-Path -Path $regPath -ErrorAction SilentlyContinue) {
        try {
            # Get all values under the key
            $regValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($regValues) {
                # Iterate through the properties (value names) of the registry key object
                # Ensure we handle cases where the key exists but has no values (PSObject is null)
                if ($regValues.PSObject) {
                    foreach ($prop in $regValues.PSObject.Properties) {
                        $valueName = $prop.Name
                        # Ignore the default value which has no name in some views
                        if ($valueName -eq '(default)') { continue }

                        # Check if the value name matches any of the patterns to remove
                        foreach ($pattern in $StartupValuePatternsToRemove) {
                            if ($valueName -like $pattern) {
                                if ($PSCmdlet.ShouldProcess("Registry Value '$valueName' under '$regPath'", "Remove Startup Entry")) {
                                    try {
                                        Remove-ItemProperty -Path $regPath -Name $valueName -Force -ErrorAction Stop
                                        Write-Host "      Removed startup entry: '$valueName' from '$regPath'" -ForegroundColor Green
                                        $startupValuesCleanedCount++
                                    } catch {
                                        Write-Error "ERROR removing startup entry '$valueName' from '$regPath': $($_.Exception.Message)"
                                    }
                                }
                                # Break inner loop once a match is found for this value name
                                break
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Warning "Error accessing or processing startup registry path '$regPath': $($_.Exception.Message)"
        }
    } else {
         # Write-Host "   Startup path not found: $regPath" -ForegroundColor DarkGray # Minimal output
    }
}
if ($startupValuesCleanedCount -gt 0) {
     Write-Host "   Removed $startupValuesCleanedCount startup registry value(s)." -ForegroundColor Green
} else {
     Write-Host "   No specific startup entries found matching patterns." -ForegroundColor DarkGray
}


# 4b: Folder Cleanup (User Profile)
$PackagesPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Packages"
# Write-Host "   Checking leftover folders in '$PackagesPath'..." -ForegroundColor DarkGray
if (Test-Path -Path $PackagesPath -PathType Container) {
    foreach ($folderPattern in $LeftoverFolderPatterns) {
        try {
            $foldersToRemove = Get-ChildItem -Path $PackagesPath -Directory -Filter $folderPattern -ErrorAction SilentlyContinue
            if ($foldersToRemove) {
                foreach ($folder in $foldersToRemove) {
                     if ($PSCmdlet.ShouldProcess($folder.FullName, "Remove Folder")) {
                        try {
                            Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
                            Write-Host "      Removed folder: $($folder.Name)" -ForegroundColor Green
                            $foldersCleanedCount++
                        } catch {
                            Write-Error "ERROR removing folder '$($folder.FullName)': $($_.Exception.Message). It might be in use or require a reboot."
                        }
                    }
                }
            }
        } catch {
             Write-Warning "Error searching for folders matching '$folderPattern' in '$PackagesPath': $($_.Exception.Message)"
        }
    }
} else {
     Write-Warning "Packages directory not found at '$PackagesPath'. Skipping leftover folder check."
}
if ($foldersCleanedCount -gt 0) {
     Write-Host "   Removed $foldersCleanedCount leftover folder(s)." -ForegroundColor Green
} else {
     Write-Host "   No leftover folders found matching patterns." -ForegroundColor DarkGray
}

# 4c: General Registry Key/Pattern Cleanup
# Write-Host "   Checking general registry locations..." -ForegroundColor DarkGray
if ($KnownLeftoverRegKeys.Count -gt 0) {
    foreach ($regKeyPathOrPattern in $KnownLeftoverRegKeys) {
        $keysToRemove = @()
        $isWildcard = $regKeyPathOrPattern -like '*[*?]*' # Check if pattern contains wildcards
        $isPath = $false # Flag to indicate if it's a specific path

        # Determine if it's a specific path or a pattern
        if ($isWildcard) {
            # It's a pattern, try to resolve it
            try {
                # Using Get-Item for registry patterns might be more reliable than Resolve-Path
                $keysToRemove = Get-Item -Path $regKeyPathOrPattern -ErrorAction SilentlyContinue
            } catch {
                 # Get-Item throws terminating error if path not found, SilentlyContinue handles that
                 # Write-Warning "Pattern '$regKeyPathOrPattern' did not resolve to any items." # Minimal output
            }
        } else {
            # It's a specific path, check if it exists
            if (Test-Path -Path $regKeyPathOrPattern -ErrorAction SilentlyContinue) {
                 $isPath = $true
                 # Treat it as a single item path to be removed directly
                 $keysToRemove = $regKeyPathOrPattern # Store the path string itself
            }
        }

        # Process the items found (could be single path string or multiple PSObjects from Get-Item)
        if ($keysToRemove) {
            # Ensure $keysToRemove is always an array for consistent looping
            $keysToRemoveArray = @($keysToRemove)
            foreach ($keyItem in $keysToRemoveArray) {
                # Get the actual path string
                # If $isPath, $keyItem is the string. If not, it's a PSObject with PSPath property.
                $actualPath = if ($isPath) { $keyItem } else { $keyItem.PSPath }

                # Double-check the path exists before attempting removal, especially for resolved patterns
                if (Test-Path -Path $actualPath -ErrorAction SilentlyContinue) {
                    if ($PSCmdlet.ShouldProcess($actualPath, "Remove Registry Key/Item")) {
                        try {
                            # Use -LiteralPath for specific paths to avoid wildcard interpretation
                            # Use -Path for resolved paths from Get-Item (which are specific)
                            # Recurse needed to remove keys with subkeys
                            if ($isPath) {
                                Remove-Item -LiteralPath $actualPath -Recurse -Force -ErrorAction Stop
                            } else {
                                Remove-Item -Path $actualPath -Recurse -Force -ErrorAction Stop
                            }
                            Write-Host "      Removed registry item: '$actualPath'" -ForegroundColor Green
                            $regKeysCleanedCount++
                        } catch {
                            Write-Error "ERROR removing registry item '$actualPath': $($_.Exception.Message)"
                        }
                    }
                } else {
                     # Write-Warning "Registry item '$actualPath' not found during removal attempt (might have been removed already)." # Minimal output
                }
            }
        }
    }
} else {
    # Write-Host "   No general leftover registry keys or patterns defined." -ForegroundColor DarkGray # Minimal output
}
if ($regKeysCleanedCount -gt 0) {
     Write-Host "   Removed $regKeysCleanedCount general registry key(s)/pattern(s)." -ForegroundColor Green
} else {
     Write-Host "   No general registry keys found matching patterns." -ForegroundColor DarkGray
}


# --- Phase 5: Verification ---
# Verification phase does not use -WhatIf as it only reads data
Write-Host "`n--- Phase 5: Verification Checks ---" -ForegroundColor Cyan
$IssuesFound = $false

# Verify AppX packages
$remainingAppX = @()
foreach ($pattern in $AppPackagePatterns) {
    try {
        $remainingAppX += Get-AppxPackage -AllUsers -Name $pattern -ErrorAction SilentlyContinue
    } catch { Write-Warning "Error during AppX verification for pattern '$pattern': $($_.Exception.Message)" }
}
if ($remainingAppX.Count -gt 0) {
    Write-Warning "   Verification FAILED: Remaining related AppX packages found:"
    $remainingAppX | Select-Object Name, PackageFullName | Format-Table -AutoSize | Out-String | Write-Warning
    $IssuesFound = $true
} else {
    Write-Host "   OK: No remaining related AppX packages found." -ForegroundColor Green
}

# Verify provisioned packages
$remainingProv = @()
foreach ($pattern in $ProvisionedPackagePatterns) {
     try {
        $remainingProv += Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like $pattern } -ErrorAction SilentlyContinue
     } catch { Write-Warning "Error during Provisioned verification for pattern '$pattern': $($_.Exception.Message)" }
}
if ($remainingProv.Count -gt 0) {
    Write-Warning "   Verification FAILED: Remaining related provisioned packages found:"
    $remainingProv | Select-Object PackageName | Format-Table -AutoSize | Out-String | Write-Warning
    $IssuesFound = $true
} else {
    Write-Host "   OK: No remaining related provisioned packages found." -ForegroundColor Green
}

# Verify service status (if any were defined)
if ($ServicesToStop.Count -gt 0) {
    try {
        $servicesStatusCheck = Get-Service -Name $ServicesToStop -ErrorAction SilentlyContinue
        if ($servicesStatusCheck) {
             Write-Warning "   Verification WARNING: Monitored services still exist (check status/startup type):"
             $servicesStatusCheck | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String | Write-Warning
             # $IssuesFound = $true # Decided not to mark as failure if service just exists but wasn't stopped
        } else {
            Write-Host "   OK: Monitored services not found." -ForegroundColor Green
        }
    } catch { Write-Warning "Error during Service verification: $($_.Exception.Message)" }
} else {
    # Write-Host "   INFO: No services configured for status check." -ForegroundColor DarkGray # Minimal output
}

# Verify scheduled tasks
$remainingTasks = @()
foreach ($pattern in $ScheduledTaskPatterns) {
    try {
        $remainingTasks += Get-ScheduledTask | Where-Object { $_.TaskName -like $pattern -or $_.TaskPath -like "*$pattern*" } -ErrorAction SilentlyContinue
    } catch { Write-Warning "Error during Scheduled Task verification for pattern '$pattern': $($_.Exception.Message)" }
}
if ($remainingTasks.Count -gt 0) {
    Write-Warning "   Verification FAILED: Found remaining related scheduled tasks:"
    $remainingTasks | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize | Out-String | Write-Warning
    $IssuesFound = $true
} else {
    Write-Host "   OK: No remaining related scheduled tasks found." -ForegroundColor Green
}

# Verify leftover folders
$foldersStillExistCheck = $false
if (Test-Path -Path $PackagesPath -PathType Container) {
    foreach ($folderPattern in $LeftoverFolderPatterns) {
        try {
            $foundFoldersCheck = Get-ChildItem -Path $PackagesPath -Directory -Filter $folderPattern -ErrorAction SilentlyContinue
            if ($foundFoldersCheck) {
                foreach ($folder in $foundFoldersCheck) {
                    Write-Warning "   Verification FAILED: Folder matching '$folderPattern' still exists: '$($folder.FullName)'"
                    $foldersStillExistCheck = $true
                }
            }
        } catch {
             Write-Warning "Error during Folder verification for pattern '$folderPattern': $($_.Exception.Message)"
        }
    }
}
if ($foldersStillExistCheck) {
     $IssuesFound = $true
} else {
    Write-Host "   OK: No leftover folders found matching patterns in '$PackagesPath'." -ForegroundColor Green
}

# Verify leftover registry keys/patterns
$regKeysStillExist = $false
# FIX 2: Check specific startup values first using corrected logic
foreach ($regPath in $StartupRegPaths) {
    if (Test-Path -Path $regPath -ErrorAction SilentlyContinue) {
        try {
            # Get the properties (values) of the registry key
            $regValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

            # Check if $regValues is not null and has properties
            if ($regValues -and $regValues.PSObject.Properties) {
                # Iterate through each property (registry value)
                foreach ($prop in $regValues.PSObject.Properties) {
                    $valueName = $prop.Name
                    # Ignore the default value
                    if ($valueName -eq '(default)') { continue }

                    # Check if this value name matches any removal pattern
                    foreach ($pattern in $StartupValuePatternsToRemove) {
                        if ($valueName -like $pattern) {
                            # If it matches, it means it wasn't removed (or shouldn't exist)
                            Write-Warning "   Verification FAILED: Startup registry value '$valueName' still exists in '$regPath'."
                            $regKeysStillExist = $true
                            # Break inner loop (patterns) once a match is found for this value name
                            break
                        }
                    }
                }
            }
        } catch { Write-Warning "Error during Startup Registry verification for path '$regPath': $($_.Exception.Message)"}
    }
}
# Check general keys/patterns
if ($KnownLeftoverRegKeys.Count -gt 0) {
    foreach ($regKeyPathOrPattern in $KnownLeftoverRegKeys) {
        try {
            # Test-Path works for both specific paths and patterns containing wildcards
            if (Test-Path -Path $regKeyPathOrPattern -ErrorAction SilentlyContinue) {
                 # If the path/pattern exists, report it. Resolve patterns to list specifics if possible.
                 $foundItems = try {
                     if ($regKeyPathOrPattern -like '*[*?]*') {
                         # Use Get-Item for patterns as it's more reliable for registry items than Resolve-Path
                         Get-Item -Path $regKeyPathOrPattern -ErrorAction SilentlyContinue
                     } else {
                         # For specific paths, just return the path itself if it exists
                         if (Test-Path -Path $regKeyPathOrPattern -ErrorAction SilentlyContinue) { $regKeyPathOrPattern } else { $null }
                     }
                 } catch { $null }

                 if ($foundItems) {
                     # Ensure $foundItems is an array
                     $foundItemsArray = @($foundItems)
                     foreach($item in $foundItemsArray){
                         # Get path string correctly whether it's an object or just the string
                         $itemPath = if ($item -is [string]) { $item } else { $item.PSPath }
                         Write-Warning "   Verification FAILED: Registry key/item matching '$regKeyPathOrPattern' still exists: '$itemPath'"
                         $regKeysStillExist = $true
                     }
                 } else {
                     # Test-Path was true, but Get-Item/Test-Path found nothing specific (e.g., access denied?)
                     # Report the original pattern/path as existing since Test-Path initially returned true
                     Write-Warning "   Verification FAILED: Registry key/pattern matching '$regKeyPathOrPattern' still exists (or could not be fully resolved/accessed)."
                     $regKeysStillExist = $true
                 }
            }
        } catch {
             Write-Warning "Error during General Registry verification for key/pattern '$regKeyPathOrPattern': $($_.Exception.Message)"
        }
    }
}
if ($regKeysStillExist) {
    $IssuesFound = $true
} else {
    Write-Host "   OK: No specified leftover registry keys, patterns, or startup values found." -ForegroundColor Green
}


# --- Script End ---
Write-Host "`n================================================" -ForegroundColor Yellow
if ($IssuesFound) {
     Write-Host "  Script finished. Verification found remaining items." -ForegroundColor Red
     Write-Warning "  Review the 'Verification FAILED' messages above."
} else {
     Write-Host "  Script finished. Verification checks passed." -ForegroundColor Green
     Write-Host "        System restart is recommended."
}
Write-Host "================================================" -ForegroundColor Yellow

# Stop Logging
if ($TranscriptActive) {
    try {
        Stop-Transcript -ErrorAction Stop *>$null
    } catch {
        # Silently ignore errors stopping transcript
    }
}


Write-Host ""
Write-Host ""
Read-Host -Prompt "Press Enter to exit..."
