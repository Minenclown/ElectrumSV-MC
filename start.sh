#!/bin/bash
# ElectrumSV-Mc Startup Script (Tauri native mode)
# Python backend has been removed — the app now runs entirely as a Tauri desktop app.
# This script launches the Tauri dev server for development.
set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

# Standalone data directory — everything stays in the project folder
export ELECTRUMSV_DATA_DIR="$PROJECT_DIR/data"
mkdir -p "$ELECTRUMSV_DATA_DIR"

echo "Starting ElectrumSV-Mc (Tauri native mode)..."
echo "  Data directory: $ELECTRUMSV_DATA_DIR"
echo ""

# Check if gui dependencies are installed
if [ ! -d "$PROJECT_DIR/gui/node_modules/vite" ]; then
    echo "Installing GUI dependencies (first run)..."
    cd "$PROJECT_DIR/gui"
    npm install
fi

# Launch Tauri dev mode (Rust backend + React frontend in one process)
cd "$PROJECT_DIR/src-tauri"
cargo tauri dev