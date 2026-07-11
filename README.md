[![License](https://img.shields.io/github/license/mirbyte/Phone-Link-Uninstaller?color=0078D7)](https://raw.githubusercontent.com/mirbyte/Phone-Link-Uninstaller/master/LICENSE)
![Size](https://img.shields.io/github/repo-size/mirbyte/Phone-Link-Uninstaller?label=size&color=0078D7)
[![Download Count](https://img.shields.io/github/downloads/mirbyte/Phone-Link-Uninstaller/total?color=0078D7)](https://github.com/mirbyte/Phone-Link-Uninstaller/releases/latest)
[![Latest Release](https://img.shields.io/github/release/mirbyte/Phone-Link-Uninstaller.svg?color=0078D7)](https://github.com/mirbyte/Phone-Link-Uninstaller/releases/latest)

# Phone Link Uninstaller
***WARNING!*** This script will attempt to forcefully remove the Phone Link (YourPhone/PhoneExperienceHost/CrossDeviceExperience) application, related components and registry entries from your system. This includes packages for all users.
While designed to be thorough, using this script may have unintended consequences or might not completely remove all traces depending on your system configuration and Windows version.
Use this script at your own risk. The author is not responsible for any damage caused.

## What it removes

- **Phone Link / Your Phone** (`Microsoft.Windows.PhoneLink`, `Microsoft.YourPhone`)
- **Phone Experience Host** (`Microsoft.PhoneExperienceHost`)
- **Cross Device Experience Host** (`MicrosoftWindows.CrossDevice`)
- **Provisioned packages** so the apps are not reinstalled for new users
- **Scheduled tasks** related to Phone Link
- **Startup entries** in common Run registry keys
- **Leftover folders** in `%LOCALAPPDATA%\Packages`
- **Registry leftovers** including Your Phone settings, the `ms-yourphone` protocol handler, and related notification/background-access keys

## Usage
1. Download the zip from **[Releases](https://github.com/mirbyte/Phone-Link-Uninstaller/releases/latest)**
2. Unzip
3. Run `start.bat`

## Alternative

If you prefer a graphical, general-purpose uninstaller, [Uninstalr](https://uninstalr.com/) is worth considering. It supports Microsoft Store apps and leftover scanning. This script remains focused specifically on removing Phone Link and its related components.

<br>

Major inspiration for the powershell script taken from [UninstallOneDrive](https://github.com/asheroto/UninstallOneDrive) & [UninstallTeams](https://github.com/asheroto/UninstallTeams) by [asheroto](https://github.com/asheroto).
