#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Network Troubleshooting for Wireshark with Amazon Bedrock - macOS/Linux installation script

set -e

echo "Installing Network Troubleshooting for Wireshark with Amazon Bedrock..."

# Detect OS
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
    echo "For Windows, use install_windows.ps1"
    exit 1
fi

# Find plugin directory
PLUGIN_DIR=""
for dir in "${POSSIBLE_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        PLUGIN_DIR="$dir"
        break
    fi
done

if [[ -z "$PLUGIN_DIR" ]]; then
    PLUGIN_DIR="${POSSIBLE_DIRS[0]}"
fi

echo "Using plugin directory: $PLUGIN_DIR"
mkdir -p "$PLUGIN_DIR"

# Verify required files exist
for file in amazon_bedrock.lua json.lua; do
    if [ ! -f "$file" ]; then
        echo "✗ $file not found in current directory"
        echo "  Run this script from the plugin source directory."
        exit 1
    fi
done

# Copy plugin files
cp amazon_bedrock.lua "$PLUGIN_DIR/"
cp json.lua "$PLUGIN_DIR/"
chmod 644 "$PLUGIN_DIR/amazon_bedrock.lua" "$PLUGIN_DIR/json.lua"
echo "✓ Plugin files copied"

# Handle config
if [ -f "config.json.example" ]; then
    cp config.json.example "$PLUGIN_DIR/"
fi

if [ ! -f "$PLUGIN_DIR/config.json" ] && [ -f "config.json.example" ]; then
    cp config.json.example "$PLUGIN_DIR/config.json"
    echo "✓ config.json created from example"
    echo ""
    echo "⚠️  IMPORTANT: Edit $PLUGIN_DIR/config.json and set your Amazon Bedrock API Key"
    echo ""
fi

# Check curl (only real dependency)
if ! command -v curl &> /dev/null; then
    echo "✗ curl not found"
    if [[ "$OS" == "macos" ]]; then
        echo "  curl should be pre-installed on macOS"
    else
        echo "  Install: sudo apt-get install curl"
    fi
    echo ""
    echo "⚠ curl is required for API calls. Install it before using the plugin."
else
    echo "✓ curl available"
    echo ""
    echo "✅ Installation complete!"
fi

echo ""
echo "Next steps:"
echo "1. Edit $PLUGIN_DIR/config.json and add your API key"
echo "2. Restart Wireshark"
echo "3. Use: Tools → Analyze with Bedrock"
