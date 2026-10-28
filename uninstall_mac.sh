#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Network Troubleshooting for Wireshark with Amazon Bedrock - macOS/Linux uninstall script

set -e

echo "Uninstalling Network Troubleshooting for Wireshark with Amazon Bedrock..."

if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    echo "Detected macOS"
    POSSIBLE_DIRS=(
        "$HOME/.local/lib/wireshark/plugins"
        "$HOME/Library/Application Support/Wireshark/plugins"
    )
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    echo "Detected Linux"
    POSSIBLE_DIRS=(
        "$HOME/.local/lib/wireshark/plugins"
    )
else
    echo "This script supports macOS and Linux only."
    echo "For Windows, use uninstall_windows.ps1"
    exit 1
fi

# Remove plugin files
removed=0
for dir in "${POSSIBLE_DIRS[@]}"; do
    for file in amazon_bedrock.lua json.lua config.json config.json.example; do
        if [[ -f "$dir/$file" ]]; then
            rm "$dir/$file"
            echo "✓ Removed: $dir/$file"
            ((removed++))
        fi
    done
done

if [[ $removed -eq 0 ]]; then
    echo "⚠ No plugin files found to remove"
else
    echo "✓ Removed $removed file(s)"
fi

# Clean up empty directories
for dir in "${POSSIBLE_DIRS[@]}"; do
    if [[ -d "$dir" ]] && [[ -z "$(ls -A "$dir" 2>/dev/null)" ]]; then
        rmdir "$dir" 2>/dev/null && echo "✓ Removed empty directory: $dir" || true
    fi
done

echo ""
echo "Restart Wireshark to complete uninstallation."
