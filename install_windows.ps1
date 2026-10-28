# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Network Troubleshooting for Wireshark with Amazon Bedrock - Windows installation script
# Run: powershell -ExecutionPolicy Bypass -File install_windows.ps1

Write-Host "Installing Network Troubleshooting for Wireshark with Amazon Bedrock..." -ForegroundColor Cyan
Write-Host ""

# Find Wireshark plugin directory
$possibleDirs = @(
    "$env:APPDATA\Wireshark\plugins",
    "$env:USERPROFILE\.local\lib\wireshark\plugins"
)

$pluginDir = $null
foreach ($dir in $possibleDirs) {
    if (Test-Path $dir) {
        $pluginDir = $dir
        break
    }
}

if (-not $pluginDir) {
    $pluginDir = $possibleDirs[0]
}

Write-Host "Plugin directory: $pluginDir"
New-Item -ItemType Directory -Force -Path $pluginDir | Out-Null

# Verify required files exist
$requiredFiles = @("amazon_bedrock.lua", "json.lua")
foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        Write-Host "X $file not found in current directory" -ForegroundColor Red
        Write-Host "  Run this script from the plugin source directory." -ForegroundColor Yellow
        exit 1
    }
}

# Copy plugin files
Copy-Item "amazon_bedrock.lua" -Destination $pluginDir -Force
Copy-Item "json.lua" -Destination $pluginDir -Force
Write-Host "OK Plugin files copied" -ForegroundColor Green

# Handle config
if (Test-Path "config.json.example") {
    Copy-Item "config.json.example" -Destination $pluginDir -Force
}

if (-not (Test-Path "$pluginDir\config.json")) {
    if (Test-Path "config.json.example") {
        Copy-Item "config.json.example" -Destination "$pluginDir\config.json" -Force
        Write-Host "OK config.json created from example" -ForegroundColor Green
    }
}

# Check curl (built into Windows 10+)
Write-Host ""
if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
    Write-Host "OK curl available" -ForegroundColor Green
} else {
    Write-Host "X curl not found" -ForegroundColor Red
    Write-Host "  curl is required for API calls. Install from https://curl.se/windows/" -ForegroundColor Yellow
    Write-Host "  (curl is built into Windows 10 and later)" -ForegroundColor Yellow
}

# Done
Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Edit $pluginDir\config.json and add your API key"
Write-Host "2. Restart Wireshark"
Write-Host "3. Use: Tools -> Analyze with Bedrock"
