# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Network Troubleshooting for Wireshark with Amazon Bedrock - Windows uninstall script
# Run: powershell -ExecutionPolicy Bypass -File uninstall_windows.ps1

Write-Host "Uninstalling Network Troubleshooting for Wireshark with Amazon Bedrock..." -ForegroundColor Cyan

$possibleDirs = @(
    "$env:APPDATA\Wireshark\plugins",
    "$env:USERPROFILE\.local\lib\wireshark\plugins"
)

$removed = 0
foreach ($dir in $possibleDirs) {
    foreach ($file in @("amazon_bedrock.lua", "json.lua", "config.json", "config.json.example")) {
        $path = Join-Path $dir $file
        if (Test-Path $path) {
            Remove-Item $path -Force
            Write-Host "OK Removed: $path" -ForegroundColor Green
            $removed++
        }
    }
}

if ($removed -eq 0) {
    Write-Host "WARNING: No plugin files found to remove" -ForegroundColor Yellow
} else {
    Write-Host "OK Removed $removed file(s)" -ForegroundColor Green
}

# Clean up empty directories
foreach ($dir in $possibleDirs) {
    if ((Test-Path $dir) -and ((Get-ChildItem $dir -Force | Measure-Object).Count -eq 0)) {
        Remove-Item $dir -Force
        Write-Host "OK Removed empty directory: $dir" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Restart Wireshark to complete uninstallation."
