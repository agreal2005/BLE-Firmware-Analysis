#!/bin/bash

# Directory containing BinExport files
BINEXPORT_DIR="./binexported_firmware"
REF_BIN="./ref_bins/ti_ble_config.o.BinExport"

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN=python
else
    echo "Error: Python is not installed." >&2
    exit 1
fi

# Loop through each .BinExport file in the directory
for file in "$BINEXPORT_DIR"/*.BinExport; do
    # Extract the firmware name (basename without extension)
    filename=$(basename -- "$file")
    firmware_name="${filename%.BinExport}"

    # Prepare results directory
    results_dir="./${firmware_name}_results"
    mkdir -p "$results_dir"
    rm -rf "${results_dir:?}/"*

    # Run bindiff
    bindiff --primary "$REF_BIN" --secondary "$file" --output_dir "$results_dir" --output_format log

    # Run match_functions.py
    $PYTHON_BIN match_functions.py "${results_dir}/ti_ble_config.o_vs_${firmware_name}.results" "./${results_dir}/matched_functions.csv"

    # Run merge_matched_functions.py
    $PYTHON_BIN merge_matched_functions.py "${results_dir}"
done

